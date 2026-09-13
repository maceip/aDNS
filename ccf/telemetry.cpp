#include "telemetry.h"
#include "ccf/ds/json.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace adns::telemetry {
namespace {
constexpr size_t MAX_BATCHES = 64;
constexpr size_t MAX_DIAGNOSTICS = 64;
constexpr size_t MAX_SPANS = MAX_DIAGNOSTICS + 3;
std::atomic<uint64_t> dropped{0};

bool hex_id(std::string_view value, size_t size) noexcept {
  return value.size() == size &&
    value.find_first_not_of("0123456789abcdef") == std::string::npos &&
    value.find_first_not_of('0') != std::string::npos;
}
std::string random_id(size_t count) {
  std::array<unsigned char, 16> bytes{};
  if(count > bytes.size() || getrandom(bytes.data(), count, GRND_NONBLOCK) !=
    static_cast<ssize_t>(count)) return {};
  static constexpr char hex[] = "0123456789abcdef";
  std::string result(count * 2, '0');
  for(size_t i = 0; i < count; ++i) {
    result[2*i] = hex[bytes[i] >> 4]; result[2*i+1] = hex[bytes[i] & 15];
  }
  return hex_id(result, count * 2) ? result : std::string{};
}
const char* outcome_name(Outcome outcome) {
  switch(outcome) {
    case Outcome::Unset: return "unset";
    case Outcome::Committed: return "committed";
    case Outcome::Rejected: return "rejected";
    case Outcome::Invalid: return "invalid";
    case Outcome::ReceiptError: return "receipt_error";
  }
  return "unset";
}
// This process owns no exporter credentials. Only this validated local socket
// path is inherited by CCF; the Python exporter owns all OTLP configuration.
std::string socket_path() {
  const char* value = std::getenv("AGENTDNS_TRACE_SOCKET");
  if(!value) return {};
  const size_t size = strnlen(value, sizeof(sockaddr_un::sun_path));
  if(size == 0 || size >= sizeof(sockaddr_un::sun_path) || value[0] != '/') return {};
  std::string path(value, size);
  if(path.find("/../") != std::string::npos || path.ends_with("/..")) return {};
  return path;
}

class Exporter final {
  static_assert(std::atomic<Batch*>::is_always_lock_free);
  static_assert(std::atomic<uint64_t>::is_always_lock_free);
  std::array<std::atomic<Batch*>, MAX_BATCHES> queue{};
  std::atomic<uint64_t> sequence{0};
  std::atomic<bool> stopping{false};
  std::string path;
  std::thread worker;
  std::unordered_map<std::string, Context> committed;
  std::deque<std::string> order;

  bool send_span(int socket, const sockaddr_un& address, Span& span,
    std::chrono::steady_clock::time_point deadline) {
    nlohmann::json attrs = nlohmann::json::object();
    if(!span.route.empty()) attrs["http.route"] = span.route;
    if(!span.method.empty()) attrs["http.request.method"] = span.method;
    if(span.http_status) attrs["http.response.status_code"] = span.http_status;
    if(span.outcome != Outcome::Unset) attrs["agentdns.outcome"] = outcome_name(span.outcome);
    if(!span.transaction_id.empty()) attrs["ccf.transaction_id"] = span.transaction_id;
    if(!span.observation_transaction_id.empty()) attrs["ccf.observation_transaction_id"] = span.observation_transaction_id;
    if(!span.zone.empty()) attrs["dns.zone"] = span.zone;
    if(span.has_serial) attrs["dns.zone.serial"] = span.serial;
    if(span.name == "ccf.request") attrs["agentdns.telemetry.dropped_batches"] = dropped.load();
    auto links = nlohmann::json::array();
    for(const auto& link : span.links) links.push_back({{"trace_id",link.trace_id},{"span_id",link.span_id}});
    nlohmann::json record = {
      {"v",1},{"trace_id",span.context.trace_id},{"span_id",span.context.span_id},
      {"parent_span_id",span.parent_span_id.empty() ? nlohmann::json(nullptr) : nlohmann::json(span.parent_span_id)},
      {"name",span.name},{"kind",span.name == "ccf.request" ? "server" : "internal"},
      {"start_unix_nanos",span.start_unix_nanos},{"end_unix_nanos",span.end_unix_nanos},
      {"status",span.status == 2 ? "error" : span.status == 1 ? "ok" : "unset"},
      {"attributes",attrs},{"links",links}
    };
    const auto data = record.dump();
    if(data.size() > 60000) return false;
    // Linux's Unix datagram receive queue can hold fewer messages than one
    // request's span batch. Give the receiver a bounded opportunity to drain.
    // This runs only on this export thread; the consensus callback never waits.
    while(std::chrono::steady_clock::now() < deadline) {
      const auto sent = sendto(socket, data.data(), data.size(), MSG_DONTWAIT | MSG_NOSIGNAL,
        reinterpret_cast<const sockaddr*>(&address), sizeof(address));
      if(sent == static_cast<ssize_t>(data.size())) return true;
      if(sent >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return false;
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
  }
  void run() noexcept {
    const int socket = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if(socket < 0) { dropped.fetch_add(1); return; }
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    while(true) {
      std::array<std::unique_ptr<Batch>,MAX_BATCHES> ready;
      size_t count=0;
      for(auto& slot:queue) {
        if(auto* value=slot.exchange(nullptr,std::memory_order_acquire))ready[count++].reset(value);
      }
      if(!count) {
        if(stopping.load())break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5)); continue;
      }
      std::sort(ready.begin(),ready.begin()+count,[](const auto& a,const auto& b){return a->sequence<b->sequence;});
      for(size_t index=0;index<count;++index)try {
        auto& batch=ready[index];
        if(batch->spans.empty()) continue;
        auto& root = batch->spans.front();
        if(!root.transaction_id.empty() && root.transaction_id != root.observation_transaction_id) {
          const auto it = committed.find(root.transaction_id);
          if(it != committed.end()) root.links.push_back(it->second);
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
        bool sent = true;
        for(auto& span : batch->spans) {
          if(!send_span(socket, address, span, deadline)) { sent = false; break; }
        }
        if(!sent) { dropped.fetch_add(1); continue; }
        // Link only to an actual completely emitted batch. Unknown or dropped
        // history remains unlinked instead of creating dangling trace links.
        if(root.outcome == Outcome::Committed && !root.transaction_id.empty() &&
           root.transaction_id == root.observation_transaction_id && !committed.contains(root.transaction_id)) {
          if(order.size() == 256) { committed.erase(order.front()); order.pop_front(); }
          committed.emplace(root.transaction_id, root.context); order.push_back(root.transaction_id);
        }
      } catch(...) { dropped.fetch_add(1); }
    }
    ::close(socket);
  }
public:
  Exporter():path(socket_path()) { if(!path.empty()) worker = std::thread([this]{run();}); }
  ~Exporter() {
    stopping.store(true); if(worker.joinable()) worker.join();
    for(auto& slot:queue)delete slot.exchange(nullptr);
  }
  bool enabled() const noexcept { return !path.empty(); }
  bool push(std::unique_ptr<Batch> batch) noexcept {
    if(!enabled() || stopping.load() || !batch || batch->spans.empty()) return false;
    batch->sequence=sequence.fetch_add(1,std::memory_order_relaxed);
    // A producer takes at most 64 CAS attempts. It never waits for another
    // producer or the socket thread, even when the consumer stops reading.
    const size_t start=batch->sequence%MAX_BATCHES;
    for(size_t offset=0;offset<MAX_BATCHES;++offset) {
      Batch* empty=nullptr;
      if(queue[(start+offset)%MAX_BATCHES].compare_exchange_strong(empty,batch.get(),
        std::memory_order_release,std::memory_order_relaxed)) {
        batch.release();return true;
      }
    }
    dropped.fetch_add(1);return false;
  }
};
Exporter& exporter() { static Exporter value; return value; }
}

uint64_t now_nanos() noexcept {
  const auto value = std::chrono::duration_cast<std::chrono::nanoseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
  return value > 0 ? static_cast<uint64_t>(value) : 0;
}
bool valid_traceparent(const std::string& value) noexcept {
  // Support W3C version 00 exactly. Ignore unknown/malformed context; it never
  // changes signed actions, authorisation, consensus, or the response result.
  const std::string_view view(value);
  return view.size() == 55 && view.starts_with("00-") && view[35] == '-' &&
    view[52] == '-' && hex_id(view.substr(3,32),32) && hex_id(view.substr(36,16),16) &&
    view.substr(53).find_first_not_of("0123456789abcdef") == std::string_view::npos;
}
bool enqueue(std::unique_ptr<Batch> batch) noexcept {
  try { return exporter().push(std::move(batch)); } catch(...) { dropped.fetch_add(1); return false; }
}
uint64_t dropped_batches() noexcept { return dropped.load(); }

Request::Request(const std::string& parent, const std::string& route, const std::string& method):
  batch(std::make_unique<Batch>()) {
  batch->spans.reserve(MAX_SPANS);
  Span root; root.name = "ccf.request"; root.route = route; root.method = method;
  root.start_unix_nanos = now_nanos(); root.context.span_id = random_id(8);
  if(valid_traceparent(parent)) {
    root.context.trace_id = parent.substr(3,32); root.parent_span_id = parent.substr(36,16);
  } else root.context.trace_id = random_id(16);
  if(root.context.trace_id.empty() || root.context.span_id.empty()) { batch.reset(); return; }
  batch->spans.push_back(std::move(root));
}
std::shared_ptr<Request> Request::start(const std::string& parent,
  const std::string& route, const std::string& method) noexcept {
  try {
    if(!exporter().enabled() || (valid_traceparent(parent) &&
      (std::strtoul(parent.c_str()+53,nullptr,16) & 1) == 0)) return {};
    auto request = std::shared_ptr<Request>(new Request(parent,route,method));
    return request->batch ? request : std::shared_ptr<Request>{};
  } catch(...) { dropped.fetch_add(1); return {}; }
}
Request::~Request() { if(!completed) finish(503,Outcome::Invalid); }
std::string Request::traceparent() const {
  return batch ? "00-" + batch->spans[0].context.trace_id + "-" + batch->spans[0].context.span_id + "-01" : "";
}
void Request::diagnostic(const std::string& name, uint64_t start, uint64_t end,
  int32_t parent_index, uint8_t status) noexcept {
  try {
    if(!batch || completed || diagnostic_failed)return;
    if(batch->spans.size() > MAX_DIAGNOSTICS || start > end || status > 2 ||
      parent_index < -1 || parent_index >= static_cast<int32_t>(batch->spans.size()) - 1) {
      diagnostic_failed=true;batch->spans.resize(1);dropped.fetch_add(1);return;
    }
    Span span; span.name = name; span.context = {batch->spans[0].context.trace_id,random_id(8)};
    if(span.context.span_id.empty()) {
      diagnostic_failed=true;batch->spans.resize(1);dropped.fetch_add(1);return;
    }
    span.parent_span_id = batch->spans[static_cast<size_t>(parent_index+1)].context.span_id;
    span.start_unix_nanos = start; span.end_unix_nanos = end; span.status = status;
    batch->spans.push_back(std::move(span));
  } catch(...) { diagnostic_failed=true;if(batch)batch->spans.resize(1);dropped.fetch_add(1); }
}
void Request::commit_wait() noexcept {
  try {
    if(!batch || completed) return;
    Span span; span.name = "ccf.commit.wait"; span.context = {batch->spans[0].context.trace_id,random_id(8)};
    if(span.context.span_id.empty()) return;
    span.parent_span_id = batch->spans[0].context.span_id; span.start_unix_nanos = now_nanos();
    commit_index = batch->spans.size(); batch->spans.push_back(std::move(span));
  } catch(...) { dropped.fetch_add(1); }
}
void Request::receipt(uint64_t start, uint64_t end, bool success) noexcept {
  try {
    if(!batch || completed || batch->spans.size() >= MAX_SPANS) return;
    Span span; span.name = "ccf.receipt"; span.context = {batch->spans[0].context.trace_id,random_id(8)};
    if(span.context.span_id.empty()) return;
    span.parent_span_id = batch->spans[0].context.span_id;
    span.start_unix_nanos = start; span.end_unix_nanos = std::max(start,end); span.status = success ? 1 : 2;
    batch->spans.push_back(std::move(span));
  } catch(...) { dropped.fetch_add(1); }
}
void Request::commit_resolved() noexcept {
  if(batch && !completed && commit_index) {
    auto& span = batch->spans[commit_index];
    span.end_unix_nanos = std::max(span.start_unix_nanos,now_nanos());
  }
}
void Request::zone(const std::string& name, uint32_t serial) noexcept {
  try {
    if(!batch || completed || name.size() > 255 || name.empty() || name.back() != '.') return;
    batch->spans[0].zone = name; batch->spans[0].serial = serial; batch->spans[0].has_serial = true;
  } catch(...) { dropped.fetch_add(1); }
}
void Request::finish(uint16_t status, Outcome outcome, const std::string& transaction_id,
  const std::string& observation_transaction_id) noexcept {
  if(completed) return;
  completed = true;
  try {
    if(!batch) return;
    auto& root = batch->spans[0];
    root.http_status = status; root.outcome = outcome; root.status = status < 400 ? 1 : 2;
    root.end_unix_nanos = std::max(root.start_unix_nanos,now_nanos());
    if(commit_index) {
      auto& wait = batch->spans[commit_index];
      if(!wait.end_unix_nanos) wait.end_unix_nanos = root.end_unix_nanos;
      wait.status = outcome == Outcome::Committed || outcome == Outcome::ReceiptError ? 1 : 2;
    }
    if(outcome == Outcome::Committed || outcome == Outcome::ReceiptError) {
      root.transaction_id = transaction_id; root.observation_transaction_id = observation_transaction_id;
    } else {
      // Nothing that speculatively appraised, signed or staged a transaction
      // is exported on rollback or an unauthenticated rejection.
      batch->spans.resize(1);
      root.zone.clear(); root.has_serial = false;
    }
    enqueue(std::move(batch));
  } catch(...) { dropped.fetch_add(1); batch.reset(); }
}
}

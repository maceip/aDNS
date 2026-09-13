#pragma once

// Transport-neutral records only. The consensus callback performs a bounded
// lock-free try-enqueue; JSON encoding and socket I/O run on the exporter thread.
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace adns::telemetry {
enum class Outcome { Unset, Committed, Rejected, Invalid, ReceiptError };
struct Context { std::string trace_id, span_id; };
struct Span {
  Context context;
  std::string parent_span_id, name, route, method, transaction_id,
    observation_transaction_id, zone;
  uint64_t start_unix_nanos = 0, end_unix_nanos = 0;
  uint32_t serial = 0;
  uint16_t http_status = 0;
  uint8_t status = 0;
  bool has_serial = false;
  Outcome outcome = Outcome::Unset;
  std::vector<Context> links;
};
struct Batch { std::vector<Span> spans; uint64_t sequence = 0; };

uint64_t now_nanos() noexcept;
bool valid_traceparent(const std::string& value) noexcept;
bool enqueue(std::unique_ptr<Batch> batch) noexcept;
uint64_t dropped_batches() noexcept;

class Request final {
  std::unique_ptr<Batch> batch;
  size_t commit_index = 0;
  bool completed = false;
  bool diagnostic_failed = false;
  Request(const std::string& parent, const std::string& route,
    const std::string& method);
public:
  static std::shared_ptr<Request> start(const std::string& parent,
    const std::string& route, const std::string& method) noexcept;
  ~Request();
  std::string traceparent() const;
  void diagnostic(const std::string& name, uint64_t start, uint64_t end,
    int32_t parent_index, uint8_t status) noexcept;
  void commit_wait() noexcept;
  void commit_resolved() noexcept;
  void receipt(uint64_t start, uint64_t end, bool success) noexcept;
  void zone(const std::string& name, uint32_t serial) noexcept;
  void finish(uint16_t status, Outcome outcome,
    const std::string& transaction_id = {},
    const std::string& observation_transaction_id = {}) noexcept;
};
}

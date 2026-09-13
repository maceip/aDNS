#include "adns-ccf/src/bridge.rs.h"
#include "adns-ccf/ccf_tx.h"
#include "ccf/kv/map.h"
#include <algorithm>
#include <array>
#include <stdexcept>

namespace adns::ffi {
using Bytes=std::vector<uint8_t>;
using RawMap=ccf::kv::RawCopySerialisedMap<Bytes,Bytes>;
static const std::array<const char*,12> tables={
  "public:agentdns.zones","public:agentdns.records","public:agentdns.registrations",
  "public:agentdns.grants","public:agentdns.nonces","public:agentdns.request_results",
  "public:agentdns.acme_challenges","public:agentdns.policies","public:agentdns.lifecycle",
  "public:agentdns.secondary_status","agentdns.private_keys","agentdns.tsig_secrets"
};
static const char* table_name(uint8_t table) {
  if(table>=tables.size()) throw std::invalid_argument("invalid agentdns collection");
  return tables[table];
}
static Bytes copy(rust::Slice<const uint8_t> bytes) {return Bytes(bytes.begin(),bytes.end());}
static rust::Vec<uint8_t> to_rust(const Bytes& bytes) {
  rust::Vec<uint8_t> out;out.reserve(bytes.size());for(auto byte:bytes)out.push_back(byte);return out;
}
Entry CcfTx::get(uint8_t table,rust::Slice<const uint8_t> key) const {
  auto* map=tx.ro<RawMap>(table_name(table));auto k=copy(key);auto value=map->get(k);
  Entry result{};result.present=value.has_value();
  if(value) {
    result.bytes=to_rust(*value);
    result.version=written.contains({table,k})?0:map->get_version_of_previous_write(k).value_or(0);
  }
  return result;
}
rust::Vec<KeyEntry> CcfTx::scan_prefix(uint8_t table,rust::Slice<const uint8_t> prefix) const {
  auto* map=tx.ro<RawMap>(table_name(table));std::vector<Bytes> keys;
  map->foreach([&](const Bytes& k,const Bytes&) {
    if(k.size()>=prefix.size() && std::equal(prefix.begin(),prefix.end(),k.begin()))keys.push_back(k);
    return true;
  });
  std::sort(keys.begin(),keys.end());rust::Vec<KeyEntry> out;out.reserve(keys.size());
  for(const auto& key:keys) {
    auto value=get(table,rust::Slice<const uint8_t>(key.data(),key.size()));
    if(value.present)out.push_back(KeyEntry{to_rust(key),std::move(value)});
  }
  return out;
}
void CcfTx::put(uint8_t table,rust::Slice<const uint8_t> key,rust::Slice<const uint8_t> value) {
  auto k=copy(key);tx.rw<RawMap>(table_name(table))->put(k,copy(value));written.insert({table,std::move(k)});
}
void CcfTx::remove(uint8_t table,rust::Slice<const uint8_t> key) {
  auto k=copy(key);tx.rw<RawMap>(table_name(table))->remove(k);written.insert({table,std::move(k)});
}
}

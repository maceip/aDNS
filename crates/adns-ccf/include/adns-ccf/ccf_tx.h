#pragma once
#include "rust/cxx.h"
#include "ccf/tx.h"
#include <cstdint>
#include <map>
#include <set>
#include <vector>

namespace adns::ffi {
struct Entry;
struct KeyEntry;
// This object never owns the CCF transaction and cannot outlive endpoint
// execution. cxx pins Rust's mutable borrow; no pointers or spans are retained.
class CcfTx final {
  ccf::kv::Tx& tx;
  std::set<std::pair<uint8_t,std::vector<uint8_t>>> written;
public:
  explicit CcfTx(ccf::kv::Tx& tx_) : tx(tx_) {}
  CcfTx(const CcfTx&)=delete;
  CcfTx& operator=(const CcfTx&)=delete;
  Entry get(uint8_t table,rust::Slice<const uint8_t> key) const;
  rust::Vec<KeyEntry> scan_prefix(uint8_t table,rust::Slice<const uint8_t> prefix) const;
  void put(uint8_t table,rust::Slice<const uint8_t> key,rust::Slice<const uint8_t> value);
  void remove(uint8_t table,rust::Slice<const uint8_t> key);
};
}

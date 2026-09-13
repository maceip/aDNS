#include "telemetry.h"
#include <cassert>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
using namespace adns::telemetry;

int main(int argc,char** argv) {
  assert(argc==2);const std::string mode=argv[1];
  const std::string parent="00-12345678901234567890123456789012-1234567890123456-01";
  assert(valid_traceparent(parent));
  for(const auto& invalid:{"", "00-00000000000000000000000000000000-1234567890123456-01",
    "00-12345678901234567890123456789012-0000000000000000-01",
    "00-12345678901234567890123456789012-1234567890123456-gg",
    "01-12345678901234567890123456789012-1234567890123456-01",
    "00-12345678901234567890123456789012-1234567890123456-01-sensitive"})
    assert(!valid_traceparent(invalid));
  if(mode=="disabled") { assert(!Request::start(parent,"/service/register","POST"));return 0; }
  if(mode=="unsampled") {
    assert(!Request::start(parent.substr(0,53)+"00","/service/register","POST"));return 0;
  }
  if(mode=="stress") {
    const auto start=std::chrono::steady_clock::now();
    std::vector<std::thread> producers;
    for(size_t t=0;t<4;++t)producers.emplace_back([&]{
      for(size_t i=0;i<2500;++i) {
        auto trace=Request::start(parent,"/service/register","POST");assert(trace);
        trace->commit_wait();trace->commit_resolved();trace->finish(200,Outcome::Committed,"2.1","2.1");
      }
    });
    for(auto& producer:producers)producer.join();
    const double seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
    std::cout<<seconds<<" "<<dropped_batches()<<"\n";assert(seconds<5);return 0;
  }
  auto trace=Request::start(mode=="malformed"?"fixture-sensitive-malformed":parent,"/service/register","POST");
  assert(trace);
  const auto start=now_nanos();
  trace->diagnostic("adns.application",start,now_nanos(),-1,1);
  trace->diagnostic("adns.auth.signature",start,now_nanos(),0,mode=="committed-error"?2:1);
  if(mode=="pressure")for(size_t i=0;i<62;++i)trace->diagnostic("adns.auth.nonce",start,now_nanos(),0,1);
  if(mode=="bad-parent")trace->diagnostic("adns.auth.nonce",start,now_nanos(),64,1);
  if(mode=="overflow")for(size_t i=0;i<65;++i)trace->diagnostic("adns.auth.nonce",start,now_nanos(),-1,1);
  trace->zone("example.test.",42);
  if(mode=="abandoned") { trace.reset();return 0; }
  if(mode=="rejected") { trace->finish(403,Outcome::Rejected);return 0; }
  trace->commit_wait();trace->commit_resolved();
  if(mode=="invalid") { trace->finish(503,Outcome::Invalid);return 0; }
  if(mode=="receipt-error") {
    trace->receipt(now_nanos(),now_nanos(),false);
    trace->finish(503,Outcome::ReceiptError,"2.1","2.1");return 0;
  }
  trace->finish(mode=="committed-error"?403:200,Outcome::Committed,"2.1","2.1");
  if(mode=="valid") {
    // The harness acknowledges receipt of the original span. This makes the
    // cache-hit case deterministic without assuming global queue ordering.
    char acknowledgement=0;std::cin.get(acknowledgement);assert(acknowledgement=='\n');
    auto retry=Request::start("","/service/request","GET");assert(retry);
    retry->commit_wait();retry->commit_resolved();retry->finish(200,Outcome::Committed,"2.1","2.2");
  }
}

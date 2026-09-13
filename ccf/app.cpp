#include "adns-ccf/src/bridge.rs.h"
#include "adns-ccf/ccf_tx.h"
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/node/node_configuration_interface.h"
#include "ccf/service/tables/service.h"
#include "ccf/receipt.h"
#include "ccf/rpc_context.h"
#include "ccf/tx_status.h"
#include <chrono>
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace adns {
static uint64_t now_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
static rust::Slice<const uint8_t> slice(const std::vector<uint8_t>& v) {return {v.data(),v.size()};}

class Handlers final:public ccf::UserEndpointRegistry {
  bool transport_guard(ccf::endpoints::EndpointContext& ctx,bool internal) {
    const auto subsystem=context.get_subsystem<ccf::NodeConfigurationInterface>();
    if(!subsystem) {ctx.rpc_ctx->set_response_status(503);ctx.rpc_ctx->set_apply_writes(false);return false;}
    const auto& interfaces=subsystem->get().node_config.network.rpc_interfaces;
    // CCF 7.0.15 delays HTTP1 responses on consensus. Reject configuration with
    // HTTP2 rather than accidentally treating its immediate response as commit.
    for(const auto& [_,interface]:interfaces) {
      if(interface.app_protocol.value_or("HTTP1")!="HTTP1") {
        ctx.rpc_ctx->set_response_json({{"error","HTTP1_REQUIRED"}},HTTP_STATUS_SERVICE_UNAVAILABLE);
        ctx.rpc_ctx->set_apply_writes(false);return false;
      }
    }
    if(internal) {
      const auto session=ctx.rpc_ctx->get_session_context();
      if(!session || session->is_forwarded || session->is_forwarding || !session->interface_id || *session->interface_id!="agentdns-internal") {
        ctx.rpc_ctx->set_response_json({{"error","INTERNAL_INTERFACE_REQUIRED"}},HTTP_STATUS_FORBIDDEN);
        ctx.rpc_ctx->set_apply_writes(false);return false;
      }
      const auto it=interfaces.find("agentdns-internal");
      if(it==interfaces.end() || !(it->second.bind_address.starts_with("127.0.0.1:") || it->second.bind_address.starts_with("[::1]:"))) {
        ctx.rpc_ctx->set_response_json({{"error","INTERNAL_LOOPBACK_REQUIRED"}},HTTP_STATUS_FORBIDDEN);
        ctx.rpc_ctx->set_apply_writes(false);return false;
      }
    }
    return true;
  }

  bool content_guard(ccf::endpoints::EndpointContext& ctx,const std::string& expected) {
    auto value=ctx.rpc_ctx->get_request_header("content-type").value_or("");
    value=value.substr(0,value.find(';'));
    while(!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))value.pop_back();
    std::transform(value.begin(),value.end(),value.begin(),[](unsigned char c){return std::tolower(c);});
    if(value!=expected) {
      ctx.rpc_ctx->set_apply_writes(false);
      ctx.rpc_ctx->set_response_json({{"error","UNSUPPORTED_MEDIA_TYPE"}},HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE);return false;
    }
    return true;
  }

  void respond(ccf::endpoints::EndpointContext& ctx,ffi::Response response) {
    // CCF skips both transaction finalisation and the consensus callback when
    // apply_writes is false, including for read-only snapshots. Successful
    // reads therefore commit their empty write set to gate the read TxID;
    // rejected application writes were discarded by the Rust overlay. Only
    // explicitly flagged authenticated attempt metadata commits on a4xx,
    // through the same global gate as successful mutations and reads.
    const bool commit_response=response.status<400 || response.commit_error;
    ctx.rpc_ctx->set_apply_writes(commit_response);
    ctx.rpc_ctx->set_response_status(response.status);
    ctx.rpc_ctx->set_response_header("content-type",std::string(response.content_type));
    std::vector<uint8_t> body(response.body.begin(),response.body.end());
    ctx.rpc_ctx->set_response_body(std::move(body));
    if(!commit_response)return;
    const bool promote_status=response.promote_status_on_commit;
    const bool json=std::string(response.content_type)=="application/json";
    const bool receipt=!response.claims_digest.empty();
    if(receipt) {
      if(response.claims_digest.size()!=32)throw std::logic_error("invalid Rust claims digest length");
      ccf::crypto::Sha256Hash::Representation digest;
      std::copy(response.claims_digest.begin(),response.claims_digest.end(),digest.begin());
      ctx.rpc_ctx->set_claims_digest(ccf::crypto::Sha256Hash::from_representation(digest));
    }
    std::optional<ccf::TxID> original;
    if(response.original_version!=0) {
      // Delayed callbacks run under CCF's Raft lock. Capture view history now;
      // invoking consensus accessors from the callback would deadlock when a
      // pending transaction later commits. The committed read snapshot proves
      // every ancestor in this captured history is also committed.
      ccf::View view;
      if(get_view_for_seqno_v1(response.original_version,view)!=ccf::ApiResult::OK) {
        ctx.rpc_ctx->set_apply_writes(false);
        ctx.rpc_ctx->set_response_json({{"status","pending"},{"error","ORIGINAL_TRANSACTION_VIEW_UNAVAILABLE"}},HTTP_STATUS_SERVICE_UNAVAILABLE);return;
      }
      original=ccf::TxID{view,response.original_version};
    }
    std::string service_cert;
    if(receipt) {const auto service=ctx.tx.ro<ccf::Service>(ccf::Tables::SERVICE)->get();if(service)service_cert=service->cert.str();}
    // No body or signed AXFR frame reaches the caller until this callback.
    ctx.rpc_ctx->set_consensus_committed_function([this,json,receipt,original,service_cert,promote_status](ccf::endpoints::CommittedTxInfo& info) {
      if(info.status!=ccf::FinalTxStatus::Committed) {
        info.rpc_ctx->set_response_json({{"status","failed"},{"error","TRANSACTION_INVALID"}},HTTP_STATUS_SERVICE_UNAVAILABLE);return;
      }
      auto txid=info.tx_id;
      if(original.has_value()) {
        if(original->seqno>info.tx_id.seqno || original->view>info.tx_id.view) {
          info.rpc_ctx->set_response_json({{"status","pending"},{"error","ORIGINAL_TRANSACTION_NOT_COMMITTED"}},HTTP_STATUS_SERVICE_UNAVAILABLE);return;
        }
        txid=*original;
      }
      info.rpc_ctx->set_response_header("x-agentdns-commit-status","committed");
      info.rpc_ctx->set_response_header("x-agentdns-transaction-id",txid.to_str());
      if(json) {
        auto result=nlohmann::json::parse(info.rpc_ctx->get_response_body());
        if(result.is_object()) {
          if(promote_status && result.contains("status") && result["status"]=="pending")result["status"]="committed";
          result["tx_id"]=txid.to_str();
          if(result.contains("execution_state")) {
            result["observation_status"]="committed";
            result["observation_tx_id"]=info.tx_id.to_str();
          }
          if(result.contains("frontend_propagation") && result["frontend_propagation"].value("status","")=="pending_commit")result["frontend_propagation"]["status"]="pending";
          if(result.contains("committed_state"))result["committed_state"]["ccf_tx_id"]=txid.to_str();
          if(receipt) {
            auto proof=ccf::endpoints::build_receipt_for_committed_tx(context,info);
            if(!proof)return; // CCF has already set the receipt error response.
            result["proof"]=ccf::describe_receipt_v1(*proof);
            result["ccf_service_identity"]=service_cert;
          }
          info.rpc_ctx->set_response_body(result.dump());
        }
      }
    });
  }
public:
  explicit Handlers(ccf::AbstractNodeContext& context):ccf::UserEndpointRegistry(context) {
    openapi_info.title="agentdns Rust authority";openapi_info.document_version="0.1.0";
  }
  void init_handlers() override {
    CommonEndpointRegistry::init_handlers();
    for(const auto& [method,path]:std::vector<std::pair<std::string,std::string>>{
      {"POST","/service/nonce"},{"POST","/service/register"},{"POST","/service/renew"},{"POST","/service/deregister"},
      {"POST","/zone/acme-challenge"},{"DELETE","/zone/acme-challenge"},{"POST","/zone/operator/records"}}) {
      make_endpoint(path,ccf::RESTVerb(method),[this,method,path](ccf::endpoints::EndpointContext& ctx){
        if(!transport_guard(ctx,false) || !content_guard(ctx,"application/json"))return;ffi::CcfTx tx(ctx.tx);
        respond(ctx,ffi::handle_mutation(tx,method,path,slice(ctx.rpc_ctx->get_request_body()),now_seconds()));
      },ccf::no_auth_required).install();
    }
    for(const auto& path:{"/service/registration","/service/request","/zone/status"}) {
      make_endpoint(path,HTTP_GET,[this,path](ccf::endpoints::EndpointContext& ctx){
        if(!transport_guard(ctx,false))return;ffi::CcfTx tx(ctx.tx);
        respond(ctx,ffi::handle_read(tx,path,ctx.rpc_ctx->get_request_query(),now_seconds()));
      },ccf::no_auth_required).install();
    }
    for(const auto& method:{"GET","POST"}) {
      make_endpoint("/dns-query",ccf::RESTVerb(std::string(method)),[this,method](ccf::endpoints::EndpointContext& ctx){
        if(!transport_guard(ctx,false) || (std::string(method)=="POST" && !content_guard(ctx,"application/dns-message")))return;
        ffi::CcfTx tx(ctx.tx);ctx.rpc_ctx->set_response_header("cache-control","no-store");
        respond(ctx,ffi::handle_doh(tx,method,ctx.rpc_ctx->get_request_query(),slice(ctx.rpc_ctx->get_request_body()),now_seconds()));
      },ccf::no_auth_required).install();
    }
    make_endpoint("/governance/ksk-receipt",HTTP_GET,[this](ccf::endpoints::EndpointContext& ctx){
      if(!transport_guard(ctx,false))return;ffi::CcfTx tx(ctx.tx);
      respond(ctx,ffi::handle_ksk_receipt(tx,ctx.rpc_ctx->get_request_query(),now_seconds()));
    },ccf::no_auth_required).install();
    make_endpoint("/internal/maintenance",HTTP_POST,[this](ccf::endpoints::EndpointContext& ctx){
      if(!transport_guard(ctx,true) || !content_guard(ctx,"application/json"))return;ffi::CcfTx tx(ctx.tx);respond(ctx,ffi::handle_maintenance(tx,now_seconds()));
    },ccf::no_auth_required).set_forwarding_required(ccf::endpoints::ForwardingRequired::Never).install();
    make_endpoint("/internal/transfer-key",HTTP_POST,[this](ccf::endpoints::EndpointContext& ctx){
      if(!transport_guard(ctx,true) || !content_guard(ctx,"application/json"))return;ffi::CcfTx tx(ctx.tx);respond(ctx,ffi::handle_transfer_key(tx,slice(ctx.rpc_ctx->get_request_body())));
    },ccf::no_auth_required).set_forwarding_required(ccf::endpoints::ForwardingRequired::Never).install();
    make_endpoint("/internal/secondary/requests",HTTP_POST,[this](ccf::endpoints::EndpointContext& ctx){
      if(!transport_guard(ctx,true) || !content_guard(ctx,"application/json"))return;ffi::CcfTx tx(ctx.tx);respond(ctx,ffi::handle_secondary_requests(tx,slice(ctx.rpc_ctx->get_request_body()),now_seconds()));
    },ccf::no_auth_required).set_forwarding_required(ccf::endpoints::ForwardingRequired::Never).install();
    make_endpoint("/internal/secondary/response",HTTP_POST,[this](ccf::endpoints::EndpointContext& ctx){
      if(!transport_guard(ctx,true) || !content_guard(ctx,"application/json"))return;ffi::CcfTx tx(ctx.tx);respond(ctx,ffi::handle_secondary_response(tx,slice(ctx.rpc_ctx->get_request_body()),now_seconds()));
    },ccf::no_auth_required).set_forwarding_required(ccf::endpoints::ForwardingRequired::Never).install();
    make_endpoint("/internal/udp",HTTP_POST,[this](ccf::endpoints::EndpointContext& ctx){
      if(!transport_guard(ctx,true) || !content_guard(ctx,"application/dns-message"))return;ffi::CcfTx tx(ctx.tx);respond(ctx,ffi::handle_udp(tx,slice(ctx.rpc_ctx->get_request_body()),now_seconds()));
    },ccf::no_auth_required).set_forwarding_required(ccf::endpoints::ForwardingRequired::Never).install();
    make_endpoint("/internal/axfr",HTTP_POST,[this](ccf::endpoints::EndpointContext& ctx){
      if(!transport_guard(ctx,true) || !content_guard(ctx,"application/dns-message"))return;ffi::CcfTx tx(ctx.tx);respond(ctx,ffi::handle_transfer(tx,slice(ctx.rpc_ctx->get_request_body()),now_seconds()));
    },ccf::no_auth_required).set_forwarding_required(ccf::endpoints::ForwardingRequired::Never).install();
  }
};
}
namespace ccf {
std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(ccf::AbstractNodeContext& context) {
  return std::make_unique<adns::Handlers>(context);
}
}

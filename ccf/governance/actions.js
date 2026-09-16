// Append after the PINNED CCF 7.0.15 default actions.js in the constitution.
// These actions run only after the consortium's normal proposal resolution.
// No action accepts or writes private signing keys or plaintext TSIG secrets.
const adnsLifecycle = "public:agentdns.lifecycle";
// CCF governance may write application maps but cannot read them. Keep
// governance-owned mirrors for proposal checks; update both atomically.
const adnsGovGrants = "public:ccf.gov.agentdns.grants";
const adnsGovConfig = "public:ccf.gov.agentdns.configuration";
const adnsGovZones = "public:ccf.gov.agentdns.zones";
const adnsGovTransfer = "public:ccf.gov.agentdns.transfers";
const adnsGovPolicies = "public:ccf.gov.agentdns.policy_identities";
function adnsObject(value, fields) {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new Error("expected object");
  const actual = Object.keys(value).sort(), expected = [...fields].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error("unknown or missing field");
}
function adnsInteger(value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error("integer outside range");
}
function adnsString(value, maximum = 512) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\x00-\x20\x7f]/.test(value)) throw new Error("invalid string");
}
function adnsName(value, underscore = false) {
  adnsString(value, 254);
  if (!value.endsWith(".") || value === ".") throw new Error("absolute name required");
  for (const label of value.slice(0, -1).split(".")) {
    if (label.length < 1 || label.length > 63 || !(underscore ? /^[a-z0-9_-]+$/ : /^[a-z0-9-]+$/).test(label) || label.startsWith("-") || label.endsWith("-")) throw new Error("canonical ASCII name required");
  }
}
function adnsHex(value) { if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error("SHA-256 lowercase hex required"); }
function adnsArray(value, validator, maximum = 512) {
  if (!Array.isArray(value) || value.length > maximum || new Set(value.map(JSON.stringify)).size !== value.length) throw new Error("bounded distinct array required");
  value.forEach(validator);
}
function adnsWireName(name) {
  adnsName(name);
  const bytes = [];
  for (const label of name.slice(0, -1).split(".")) {bytes.push(label.length);for (const char of label) bytes.push(char.charCodeAt(0));}
  bytes.push(0);return new Uint8Array(bytes).buffer;
}
function adnsWrite(table, key, value) {ccf.kv[table].set(key, ccf.jsonCompatibleToBuf(value));}
// Exact JSON identity: object order is irrelevant; array order and every
// explicit field remain significant. Bounds apply before recursion/encoding.
function adnsPolicyIdentity(policy) {
  const fields=["policy_id","release_id","active_profiles","valid_from","valid_until","max_appraisal_lifetime","minimum_tcb","approved_measurements","approved_host_data","uvm"];
  adnsObject(policy,Object.prototype.hasOwnProperty.call(policy || {},"uvm_endorsement_time_policy") ? [...fields,"uvm_endorsement_time_policy"] : fields);
  if(!Array.isArray(policy.policy_id)||policy.policy_id.length!==32)throw new Error("policy_id must contain 32 bytes");
  policy.policy_id.forEach(v=>adnsInteger(v,0,255));
  if(policy.policy_id.every(v=>v===0))throw new Error("nonzero policy_id required");
  let nodes=0, bytes=0;
  function account(encoded) {
    bytes+=ccf.strToBuf(encoded).byteLength;
    if(bytes>65536)throw new Error("policy exceeds 64 KiB");
    return encoded;
  }
  function canonical(value,depth) {
    if(++nodes>4096||depth>8)throw new Error("policy structure exceeds bounds");
    if(value===null||typeof value==="boolean")return account(JSON.stringify(value));
    if(typeof value==="number"){adnsInteger(value);if(Object.is(value,-0))throw new Error("negative zero not allowed");return account(JSON.stringify(value));}
    if(typeof value==="string") {
      if(value.length>65536)throw new Error("policy string exceeds bounds");
      for(let i=0;i<value.length;i++) {
        const c=value.charCodeAt(i);
        if(c>=0xd800&&c<=0xdbff){const next=value.charCodeAt(++i);if(!(next>=0xdc00&&next<=0xdfff))throw new Error("invalid Unicode string");}
        else if(c>=0xdc00&&c<=0xdfff)throw new Error("invalid Unicode string");
      }
      return account(JSON.stringify(value));
    }
    if(Array.isArray(value)){if(value.length>4096)throw new Error("policy array exceeds bounds");account("[]"+",".repeat(Math.max(0,value.length-1)));return "["+value.map(v=>canonical(v,depth+1)).join(",")+"]";}
    if(typeof value==="object") {
      const keys=Object.keys(value).sort();
      if(keys.length>4096)throw new Error("policy object exceeds bounds");
      account("{}"+":".repeat(keys.length)+",".repeat(Math.max(0,keys.length-1)));
      return "{"+keys.map(k=>canonical(k,depth+1)+":"+canonical(value[k],depth+1)).join(",")+"}";
    }
    throw new Error("non-JSON policy value");
  }
  const encoded=canonical(policy,0);
  if(ccf.strToBuf(encoded).byteLength>65536)throw new Error("policy exceeds 64 KiB");
  return {key:ccf.strToBuf(policy.policy_id.map(v=>v.toString(16).padStart(2,"0")).join("")),canonical:encoded};
}
function adnsGrant(grant) {
  // attested_names/attested_record_types (attested-path TXT such as DKIM and
  // receipt keys) and the "anchor" operation were added for the agent-hosting
  // shared interface. Grants committed before then deserialize with empty lists.
  adnsObject(grant,["grant_id","subject_spki_sha256","zones","mailbox_domains","service_hosts","roles","address_cidrs","ports","allowed_operations","acme_names","operator_names","operator_record_types","attested_names","attested_record_types","max_lease_seconds","max_challenge_lifetime_seconds","valid_from","valid_until","revoked"]);
  adnsString(grant.grant_id,128);adnsHex(grant.subject_spki_sha256);
  for (const key of ["zones","mailbox_domains","service_hosts","acme_names"]) adnsArray(grant[key],v=>adnsName(v));
  adnsArray(grant.operator_names,v=>adnsName(v,true));
  adnsArray(grant.attested_names,v=>adnsName(v,true));
  for (const key of ["roles","address_cidrs"]) adnsArray(grant[key],v=>adnsString(v,128));
  adnsArray(grant.ports,v=>adnsInteger(v,1,65535),128);
  if (grant.ports.some((v,i)=>i>0 && grant.ports[i-1]>=v)) throw new Error("ports must be sorted");
  const operations=["register","renew","deregister","acme_challenge_create","acme_challenge_delete","operator_records","anchor"];
  adnsArray(grant.allowed_operations,v=>{if(!operations.includes(v))throw new Error("unknown operation");});
  adnsArray(grant.operator_record_types,v=>{if(!["A","AAAA","NS","CNAME","MX","TXT","CAA"].includes(v))throw new Error("unknown operator type");});
  adnsArray(grant.attested_record_types,v=>{if(!["TXT"].includes(v))throw new Error("unknown attested type");});
  if((grant.attested_names.length>0)!==(grant.attested_record_types.length>0))throw new Error("attested names and types go together");
  for (const key of ["max_lease_seconds","max_challenge_lifetime_seconds"]) adnsInteger(grant[key],1);
  adnsInteger(grant.valid_from);adnsInteger(grant.valid_until,grant.valid_from+1);
  if(typeof grant.revoked!=="boolean" || grant.zones.length===0 || grant.allowed_operations.length===0)throw new Error("invalid grant");
}
actions.set("adns_set_owner_grant", new Action(
  args=>{adnsObject(args,["grant"]);adnsGrant(args.grant);},
  args=>{const key=ccf.strToBuf(args.grant.grant_id);adnsWrite(adnsGovGrants,key,args.grant);adnsWrite("public:agentdns.grants",key,args.grant);}
));
actions.set("adns_revoke_owner_grant", new Action(
  args=>{adnsObject(args,["grant_id"]);adnsString(args.grant_id,128);},
  args=>{const key=ccf.strToBuf(args.grant_id), old=ccf.kv[adnsGovGrants].get(key);if(old===undefined)throw new Error("grant missing");const grant=ccf.bufToJsonCompatible(old);grant.revoked=true;adnsWrite(adnsGovGrants,key,grant);adnsWrite("public:agentdns.grants",key,grant);}
));
actions.set("adns_set_configuration", new Action(
  args=>{adnsObject(args,["audience","epoch","last_time"]);adnsString(args.audience);adnsInteger(args.epoch,1);adnsInteger(args.last_time);},
  args=>{const key=ccf.strToBuf("configuration"),old=ccf.kv[adnsGovConfig].get(key);if(old!==undefined){const config=ccf.bufToJsonCompatible(old);if(args.epoch<=config.epoch)throw new Error("configuration epoch must advance");}adnsWrite(adnsGovConfig,key,args);adnsWrite(adnsLifecycle,ccf.strToBuf("governance/configuration"),args);}
));
// ---- Release authority D and signed policy changes (shared interface items 1, 9) ----
const adnsGovReleaseAuthority = "public:ccf.gov.agentdns.release_authority";
const adnsGovNodeJoinPolicy = "public:ccf.gov.agentdns.node_join_policy";
function adnsBase64Url(value, maximum) {
  adnsString(value, maximum);
  if(!/^[A-Za-z0-9_-]+$/.test(value)||value.length%4===1)throw new Error("base64url required");
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const out=[];let bits=0,acc=0;
  for(const c of value){acc=(acc<<6)|alphabet.indexOf(c);bits+=6;if(bits>=8){bits-=8;out.push((acc>>bits)&0xff);}}
  if(acc&((1<<bits)-1))throw new Error("noncanonical base64url");
  return new Uint8Array(out).buffer;
}
function adnsHexOf(buffer){return Array.from(new Uint8Array(buffer)).map(b=>b.toString(16).padStart(2,"0")).join("");}
// Fixed 64-byte r||s (the same convention as service request signatures)
// converted to DER for ccf.crypto.verifySignature.
function adnsEcdsaDer(raw) {
  const bytes=new Uint8Array(raw);
  if(bytes.length!==64)throw new Error("fixed-width P-256 signature required");
  const integer=part=>{let i=0;while(i<part.length-1&&part[i]===0)i++;let body=Array.from(part.slice(i));if(body[0]&0x80)body=[0,...body];return [0x02,body.length,...body];};
  const r=integer(bytes.slice(0,32)), s=integer(bytes.slice(32));
  return new Uint8Array([0x30,r.length+s.length,...r,...s]).buffer;
}
// JCS-equivalent canonical JSON for bounded values of strings, safe integers,
// booleans, null, arrays and objects (the same value space adnsPolicyIdentity accepts).
function adnsCanonical(value) {
  let nodes=0;
  function canonical(v,depth){
    if(++nodes>4096||depth>8)throw new Error("structure exceeds bounds");
    if(v===null||typeof v==="boolean")return JSON.stringify(v);
    if(typeof v==="number"){adnsInteger(v);return JSON.stringify(v);}
    if(typeof v==="string"){if(v.length>65536)throw new Error("string exceeds bounds");return JSON.stringify(v);}
    if(Array.isArray(v)){if(v.length>4096)throw new Error("array exceeds bounds");return "["+v.map(x=>canonical(x,depth+1)).join(",")+"]";}
    if(typeof v==="object"){const keys=Object.keys(v).sort();return "{"+keys.map(k=>JSON.stringify(k)+":"+canonical(v[k],depth+1)).join(",")+"}";}
    throw new Error("non-JSON value");
  }
  return canonical(value,0);
}
function adnsReleaseAuthority() {
  const raw=ccf.kv[adnsGovReleaseAuthority].get(ccf.strToBuf("release-authority"));
  return raw===undefined?undefined:ccf.bufToJsonCompatible(raw);
}
// A change signed by D: `signature` is {did, svn, signature} over the canonical
// JSON of {"svn":svn,"payload":payload}. svn must equal the authority's current
// svn or advance it by exactly one (anti-rollback, no skipping).
function adnsRequireAuthoritySignature(payload, signature, purpose) {
  const authority=adnsReleaseAuthority();
  if(authority===undefined)throw new Error("release authority not set; "+purpose+" requires a governed release authority");
  adnsObject(signature,["did","svn","signature"]);
  if(signature.did!==authority.did)throw new Error("signature DID differs from the governed release authority");
  adnsInteger(signature.svn,authority.svn,authority.svn+1);
  const message=ccf.strToBuf(adnsCanonical({svn:signature.svn,payload}));
  const der=adnsEcdsaDer(adnsBase64Url(signature.signature,128));
  if(!ccf.crypto.verifySignature({name:"ECDSA",hash:"SHA-256"},authority.public_key_pem,der,message))throw new Error("release authority signature invalid for "+purpose);
  if(signature.svn>authority.svn){
    // The authority record's svn is the high-water mark of everything D has signed.
    const ratcheted={...authority,svn:signature.svn};
    adnsWrite(adnsGovReleaseAuthority,ccf.strToBuf("release-authority"),ratcheted);
    adnsWrite(adnsLifecycle,ccf.strToBuf("governance/release-authority"),ratcheted);
  }
  return signature.svn;
}
actions.set("adns_set_release_authority", new Action(
  args=>{
    adnsObject(args,["authority"]);
    adnsObject(args.authority,["did","public_key_pem","svn","valid_from","valid_until"]);
    adnsString(args.authority.did,512);
    if(!/^did:x509:0:sha256:[A-Za-z0-9_-]+::/.test(args.authority.did))throw new Error("did:x509 required");
    if(typeof args.authority.public_key_pem!=="string"||!/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?$/.test(args.authority.public_key_pem)||args.authority.public_key_pem.length>2048)throw new Error("SPKI PEM required");
    adnsInteger(args.authority.svn,0);adnsInteger(args.authority.valid_from);adnsInteger(args.authority.valid_until,args.authority.valid_from+1);
  },
  (args,proposalId)=>{
    const key=ccf.strToBuf("release-authority"), old=adnsReleaseAuthority();
    // Rotation never lowers the SVN floor; a new key starts where the old one stopped.
    if(old!==undefined && args.authority.svn<old.svn)throw new Error("release authority svn cannot regress");
    adnsWrite(adnsGovReleaseAuthority,key,args.authority);
    adnsWrite(adnsLifecycle,ccf.strToBuf("governance/release-authority"),args.authority);
    if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);
  }
));
// Replaces ad-hoc add_snp_measurement/add_snp_host_data/add_snp_uvm_endorsement
// for primary upgrades: one signed, SVN-ratcheted policy that SETS the exact
// node join tables (removing anything not listed), so a retired release cannot
// rejoin and the accepted set is always what D last signed.
function adnsNodeJoinPolicy(policy) {
  adnsObject(policy,["svn","release_id","measurements","host_data","uvm_endorsements","tcb_versions"]);
  adnsInteger(policy.svn,1);adnsString(policy.release_id,128);
  adnsArray(policy.measurements,v=>{if(typeof v!=="string"||!/^[0-9a-f]{96}$/.test(v))throw new Error("SNP measurement hex required");},64);
  adnsArray(policy.host_data,v=>{adnsHex(v);},64);
  adnsArray(policy.uvm_endorsements,v=>{adnsObject(v,["did","feed","svn"]);adnsString(v.did,512);adnsString(v.feed,128);adnsString(v.svn,16);if(!/^[0-9]+$/.test(v.svn))throw new Error("uvm svn digits");},64);
  if(policy.measurements.length===0||policy.host_data.length===0||policy.uvm_endorsements.length===0)throw new Error("node join policy must list measurements, host data and UVM endorsements");
  adnsObject(policy.tcb_versions,Object.keys(policy.tcb_versions));
  const cpuids=Object.keys(policy.tcb_versions);
  if(cpuids.length===0||cpuids.length>16)throw new Error("tcb_versions per cpuid required");
  for(const cpuid of cpuids){adnsString(cpuid,64);adnsObject(policy.tcb_versions[cpuid],["boot_loader","tee","snp","microcode"]);for(const f of ["boot_loader","tee","snp","microcode"])adnsInteger(policy.tcb_versions[cpuid][f],0,255);}
}
actions.set("adns_set_node_join_policy", new Action(
  args=>{adnsObject(args,["policy","signature"]);adnsNodeJoinPolicy(args.policy);adnsObject(args.signature,["did","svn","signature"]);},
  (args,proposalId)=>{
    const key=ccf.strToBuf("node-join-policy"), raw=ccf.kv[adnsGovNodeJoinPolicy].get(key);
    const current=raw===undefined?undefined:ccf.bufToJsonCompatible(raw);
    if(current!==undefined && args.policy.svn<=current.svn)throw new Error("node join policy svn must advance (anti-rollback)");
    const svn=adnsRequireAuthoritySignature(args.policy,args.signature,"node join policy");
    if(svn!==args.policy.svn)throw new Error("signature svn must equal policy svn");
    // SET semantics on CCF's own join tables.
    const measurements=ccf.kv["public:ccf.gov.nodes.snp.measurements"], hostData=ccf.kv["public:ccf.gov.nodes.snp.host_data"], uvm=ccf.kv["public:ccf.gov.nodes.snp.uvm_endorsements"], tcb=ccf.kv["public:ccf.gov.nodes.snp.tcb_versions"];
    for(const table of [measurements,hostData,uvm,tcb]) if(typeof table.clear==="function") table.clear(); else table.forEach((_,k)=>table.delete(k));
    for(const m of args.policy.measurements) measurements.set(ccf.strToBuf(m),ccf.jsonCompatibleToBuf("AllowedToJoin"));
    for(const h of args.policy.host_data) hostData.set(ccf.strToBuf(h),ccf.jsonCompatibleToBuf(""));
    const byDid={};
    for(const e of args.policy.uvm_endorsements){byDid[e.did]=byDid[e.did]||{};byDid[e.did][e.feed]={svn:e.svn};}
    for(const did of Object.keys(byDid)) uvm.set(ccf.strToBuf(did),ccf.jsonCompatibleToBuf(byDid[did]));
    for(const cpuid of Object.keys(args.policy.tcb_versions)) tcb.set(ccf.strToBuf(cpuid),ccf.jsonCompatibleToBuf(args.policy.tcb_versions[cpuid]));
    const record={...args.policy,policy_sha256:adnsHexOf(ccf.crypto.digest("SHA-256",ccf.strToBuf(adnsCanonical(args.policy)))),signed_by:args.signature.did};
    adnsWrite(adnsGovNodeJoinPolicy,key,record);
    adnsWrite(adnsLifecycle,ccf.strToBuf("governance/node-join-policy"),record);
    if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);
  }
));
actions.set("adns_set_appraisal_policy", new Action(
  args=>{
    const fields=Object.prototype.hasOwnProperty.call(args||{},"signature")?["zone","policy","signature"]:["zone","policy"];
    adnsObject(args,fields);adnsName(args.zone);adnsPolicyIdentity(args.policy);
    if(fields.length===3)adnsObject(args.signature,["did","svn","signature"]);
  },
  (args,proposalId)=>{
    const identity=adnsPolicyIdentity(args.policy), old=ccf.kv[adnsGovPolicies].get(identity.key);
    if(old!==undefined && ccf.bufToJsonCompatible(old).canonical!==identity.canonical)throw new Error("policy contents changed; use a new policy_id");
    if(old===undefined && ccf.kv[adnsGovPolicies].size>=512)throw new Error("maximum 512 immutable appraisal policy identities");
    // Once a release authority is governed, every workload policy must carry
    // its signature; unsigned policies were the pre-D bootstrap path only.
    if(adnsReleaseAuthority()!==undefined){
      if(args.signature===undefined)throw new Error("appraisal policy requires the release authority signature");
      adnsRequireAuthoritySignature(args.policy,args.signature,"appraisal policy");
    }
    adnsWrite(adnsGovPolicies,identity.key,{canonical:identity.canonical});
    adnsWrite("public:agentdns.policies",adnsWireName(args.zone),args.policy);
    if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);
  }
));
actions.set("adns_create_zone", new Action(
  args=>{adnsObject(args,["metadata"]);adnsObject(args.metadata,["id","origin","serial","base_records","signed_records","signature_validity","refresh_before","last_signed_at","earliest_signature_expiration","maintenance_health","ksk_dnskey_rdata"]);adnsName(args.metadata.origin);adnsInteger(args.metadata.signature_validity,600,2147483647);adnsInteger(args.metadata.refresh_before,300,args.metadata.signature_validity-1);if(!Array.isArray(args.metadata.base_records)||args.metadata.base_records.length===0||args.metadata.base_records.length>4096)throw new Error("base records required");if(args.metadata.signed_records.length!==0||args.metadata.ksk_dnskey_rdata.length!==0)throw new Error("signing material generated in enclave only");},
  args=>{const key=adnsWireName(args.metadata.origin);if(ccf.kv[adnsGovZones].has(key))throw new Error("zone already governed");if(ccf.kv[adnsGovZones].size>=32)throw new Error("maximum 32 governed zones");adnsWrite(adnsGovZones,key,args.metadata);adnsWrite(adnsLifecycle,ccf.strToBuf("governance/zone/"+args.metadata.origin),args.metadata);}
));
actions.set("adns_set_transfer", new Action(
  args=>{adnsObject(args,["key_name","endpoint","zones","secret_sha256"]);adnsName(args.key_name);adnsString(args.endpoint,128);adnsHex(args.secret_sha256);adnsArray(args.zones,v=>adnsName(v),128);if(args.zones.length===0)throw new Error("zone scope required");},
  args=>{const key=ccf.strToBuf("governance/transfer/"+args.key_name),old=ccf.kv[adnsGovTransfer].get(key);if(old===undefined && ccf.kv[adnsGovTransfer].size>=512)throw new Error("maximum 512 governed transfer key identities");if(old!==undefined){const existing=ccf.bufToJsonCompatible(old);if(existing.revoked===true)throw new Error("transfer identity permanently revoked; use a new key_name");if(existing.secret_sha256!==args.secret_sha256 || existing.endpoint!==args.endpoint)throw new Error("new endpoint or secret requires new key_name");}adnsWrite(adnsGovTransfer,key,args);adnsWrite(adnsLifecycle,key,args);}
));
actions.set("adns_revoke_transfer", new Action(
  args=>{adnsObject(args,["key_name"]);adnsName(args.key_name);},
  args=>{const key=ccf.strToBuf("governance/transfer/"+args.key_name),old=ccf.kv[adnsGovTransfer].get(key);if(old===undefined)throw new Error("transfer identity missing");const revoked=ccf.bufToJsonCompatible(old);revoked.revoked=true;adnsWrite(adnsGovTransfer,key,revoked);adnsWrite(adnsLifecycle,key,revoked);}
));
// ---- Governors: open-join, reputation-weighted, agent-led, with a human trap door ----
// Shape (agent-hosting ADR 0025 / agentdns ADR 0002): members are verifier agents
// (class "agent") or humans (class "trapdoor"). Votes are weighted by reputation,
// earned by verdicts that agree with outcomes and lost by verdicts that do not.
// A `block` verdict (a BountyNet-style finding) holds a release proposal open until
// withdrawn. A trapdoor vote is decisive either way and is loud in the ledger.
const adnsGovGovernors = "public:ccf.gov.agentdns.governors";
const adnsGovVerdicts = "public:ccf.gov.agentdns.verdicts";
const adnsGovSettled = "public:ccf.gov.agentdns.settled";
const adnsGovParams = "public:ccf.gov.agentdns.governance";
const adnsHighImpact = ["set_constitution","set_js_app","set_member","remove_member","set_recovery_threshold","transition_service_to_open",
  "add_snp_measurement","add_snp_host_data","add_snp_uvm_endorsement","set_snp_minimum_tcb_version","set_snp_minimum_tcb_version_hex",
  "remove_snp_measurement","remove_snp_host_data","remove_snp_uvm_endorsement","remove_snp_minimum_tcb_version",
  "adns_set_node_join_policy","adns_set_appraisal_policy","adns_set_release_authority","adns_set_governance_parameters","adns_set_governor"];
function adnsDefaultParams() {
  return {release_threshold:[2,3],block_threshold:[1,3],routine_threshold:[1,2],min_agent_yes:1,newcomer_weight_cap_percent:20,
    max_member_weight_percent:34,reputation_min:1,reputation_max:64,reputation_step:1,block_reputation:2,open_join:true,high_impact_actions:adnsHighImpact};
}
function adnsParams() {
  const raw=ccf.kv[adnsGovParams].get(ccf.strToBuf("parameters"));
  return raw===undefined?adnsDefaultParams():{...adnsDefaultParams(),...ccf.bufToJsonCompatible(raw)};
}
function adnsGovernorOf(memberId, params) {
  const raw=ccf.kv[adnsGovGovernors].get(ccf.strToBuf(memberId));
  return raw===undefined?{class:"agent",reputation:params.reputation_min,joined_via:"unregistered"}:ccf.bufToJsonCompatible(raw);
}
function adnsText(value, maximum) { if (typeof value !== "string" || value.length > maximum || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) throw new Error("invalid text"); }
function adnsRatio(value) { if(!Array.isArray(value)||value.length!==2)throw new Error("ratio [num,den] required");adnsInteger(value[0],0,1000);adnsInteger(value[1],1,1000);if(value[0]>value[1])throw new Error("ratio above one"); }
actions.set("adns_set_governance_parameters", new Action(
  args=>{
    adnsObject(args,["parameters"]);
    const p=args.parameters, keys=Object.keys(adnsDefaultParams());
    adnsObject(p,Object.keys(p).filter(k=>keys.includes(k)));
    for(const k of ["release_threshold","block_threshold","routine_threshold"]) if(k in p) adnsRatio(p[k]);
    if("min_agent_yes" in p) adnsInteger(p.min_agent_yes,1,64);
    for(const k of ["newcomer_weight_cap_percent","max_member_weight_percent"]) if(k in p) adnsInteger(p[k],1,100);
    for(const k of ["reputation_min","reputation_max","reputation_step","block_reputation"]) if(k in p) adnsInteger(p[k],1,1000000);
    if("reputation_min" in p && "reputation_max" in p && p.reputation_min>p.reputation_max) throw new Error("reputation bounds");
    if("open_join" in p && typeof p.open_join!=="boolean") throw new Error("open_join boolean");
    if("high_impact_actions" in p) adnsArray(p.high_impact_actions,v=>adnsString(v,128),128);
  },
  (args,proposalId)=>{adnsWrite(adnsGovParams,ccf.strToBuf("parameters"),{...adnsParams(),...args.parameters});adnsWrite(adnsLifecycle,ccf.strToBuf("governance/parameters"),{...adnsParams(),...args.parameters});if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);}
));
// Register or reclassify a member as a governor. Open join: any member may be
// proposed by any member; admission is decided by the weighted vote like any
// other high-impact proposal. Reputation is set only at registration (to the
// minimum unless a trapdoor is being registered) and thereafter only by settle.
actions.set("adns_set_governor", new Action(
  args=>{
    adnsObject(args,["member_id","class","note"]);adnsString(args.member_id,64);
    if(!/^[0-9a-f]{64}$/.test(args.member_id))throw new Error("member_id is a 64-hex CCF member id");
    if(!["agent","trapdoor"].includes(args.class))throw new Error("class agent|trapdoor");adnsString(args.note,512);
  },
  (args,proposalId)=>{
    const params=adnsParams(), key=ccf.strToBuf(args.member_id), old=ccf.kv[adnsGovGovernors].get(key);
    const existing=old===undefined?undefined:ccf.bufToJsonCompatible(old);
    const record={class:args.class,reputation:existing?existing.reputation:params.reputation_min,joined_via:existing?existing.joined_via:proposalId,note:args.note};
    adnsWrite(adnsGovGovernors,key,record);adnsWrite(adnsLifecycle,ccf.strToBuf("governance/governor/"+args.member_id),record);
    if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);
  }
));
// A verdict is a self-attesting statement by the proposing member about another
// proposal: approve, block (a finding), or withdraw (of its own block). It is
// accepted by resolve() on the proposer's word alone because it only writes the
// verdict table; its effect on the target proposal comes through resolve().
actions.set("adns_record_verdict", new Action(
  args=>{
    adnsObject(args,["proposal_id","verdict","checks","evidence","rationale"]);
    if(!/^[0-9a-f]{64}$/.test(args.proposal_id))throw new Error("proposal_id is a 64-hex CCF proposal id");
    if(!["approve","block","withdraw"].includes(args.verdict))throw new Error("verdict approve|block|withdraw");
    adnsArray(args.checks,c=>{adnsObject(c,["name","passed","detail"]);adnsString(c.name,64);if(typeof c.passed!=="boolean")throw new Error("passed boolean");adnsText(c.detail,1024);},64);
    if(args.verdict==="block" && !args.checks.some(c=>c.passed===false))throw new Error("a block verdict needs at least one failed check");
    adnsObject(args.evidence,Object.keys(args.evidence));for(const k of Object.keys(args.evidence)){adnsString(k,64);adnsText(args.evidence[k],4096);}
    if(Object.keys(args.evidence).length>32)throw new Error("evidence keys");adnsText(args.rationale,4096);
  },
  (args,proposalId)=>{
    const raw=ccf.kv["public:ccf.gov.proposals_info"].get(ccf.strToBuf(proposalId));
    if(raw===undefined)throw new Error("verdict proposal has no info");
    const proposer=ccf.bufToJsonCompatible(raw).proposer_id;
    const record={...args,by:proposer,in_proposal:proposalId};
    adnsWrite(adnsGovVerdicts,ccf.strToBuf(args.proposal_id+"/"+proposer),record);
    adnsWrite(adnsLifecycle,ccf.strToBuf("governance/verdict/"+args.proposal_id+"/"+proposer),record);
  }
));
// Settle reputation for a resolved proposal, once: voters on the winning side gain
// a step, voters on the losing side lose a step, within [min, max]. Any member may
// propose settlement; the ledger's own final_votes are the only input.
actions.set("adns_settle", new Action(
  args=>{adnsObject(args,["proposal_id"]);if(!/^[0-9a-f]{64}$/.test(args.proposal_id))throw new Error("proposal_id is a 64-hex CCF proposal id");},
  (args,proposalId)=>{
    const key=ccf.strToBuf(args.proposal_id);
    if(ccf.kv[adnsGovSettled].has(key))throw new Error("already settled");
    const raw=ccf.kv["public:ccf.gov.proposals_info"].get(key);
    if(raw===undefined)throw new Error("unknown proposal");
    const info=ccf.bufToJsonCompatible(raw);
    if(!["Accepted","Rejected"].includes(info.state))throw new Error("proposal not resolved");
    const params=adnsParams(), winning=info.state==="Accepted", changes={};
    for(const [memberId,vote] of Object.entries(info.final_votes||{})) {
      const g=adnsGovernorOf(memberId,params);
      if(g.class!=="agent")continue;
      const delta=(vote===winning)?params.reputation_step:-params.reputation_step;
      const next=Math.max(params.reputation_min,Math.min(params.reputation_max,g.reputation+delta));
      if(next!==g.reputation){changes[memberId]=[g.reputation,next];adnsWrite(adnsGovGovernors,ccf.strToBuf(memberId),{...g,reputation:next});}
    }
    const record={state:info.state,changes,settled_in:proposalId};
    adnsWrite(adnsGovSettled,key,record);adnsWrite(adnsLifecycle,ccf.strToBuf("governance/settled/"+args.proposal_id),record);
  }
));

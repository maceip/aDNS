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
  adnsObject(grant,["grant_id","subject_spki_sha256","zones","mailbox_domains","service_hosts","roles","address_cidrs","ports","allowed_operations","acme_names","operator_names","operator_record_types","max_lease_seconds","max_challenge_lifetime_seconds","valid_from","valid_until","revoked"]);
  adnsString(grant.grant_id,128);adnsHex(grant.subject_spki_sha256);
  for (const key of ["zones","mailbox_domains","service_hosts","acme_names"]) adnsArray(grant[key],v=>adnsName(v));
  adnsArray(grant.operator_names,v=>adnsName(v,true));
  for (const key of ["roles","address_cidrs"]) adnsArray(grant[key],v=>adnsString(v,128));
  adnsArray(grant.ports,v=>adnsInteger(v,1,65535),128);
  if (grant.ports.some((v,i)=>i>0 && grant.ports[i-1]>=v)) throw new Error("ports must be sorted");
  const operations=["register","renew","deregister","acme_challenge_create","acme_challenge_delete","operator_records"];
  adnsArray(grant.allowed_operations,v=>{if(!operations.includes(v))throw new Error("unknown operation");});
  adnsArray(grant.operator_record_types,v=>{if(!["A","AAAA","NS","CNAME","MX","TXT","CAA"].includes(v))throw new Error("unknown operator type");});
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
actions.set("adns_set_appraisal_policy", new Action(
  args=>{adnsObject(args,["zone","policy"]);adnsName(args.zone);adnsPolicyIdentity(args.policy);},
  args=>{
    const identity=adnsPolicyIdentity(args.policy), old=ccf.kv[adnsGovPolicies].get(identity.key);
    if(old!==undefined && ccf.bufToJsonCompatible(old).canonical!==identity.canonical)throw new Error("policy contents changed; use a new policy_id");
    if(old===undefined && ccf.kv[adnsGovPolicies].size>=512)throw new Error("maximum 512 immutable appraisal policy identities");
    adnsWrite(adnsGovPolicies,identity.key,{canonical:identity.canonical});
    adnsWrite("public:agentdns.policies",adnsWireName(args.zone),args.policy);
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

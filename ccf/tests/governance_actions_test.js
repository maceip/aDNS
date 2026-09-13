// Exercise the actual application constitution actions with a write-only app
// map boundary. Real CCF transactional/governance coverage is control_smoke.py.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../governance/actions.js'), 'utf8');
const transferTable = 'public:ccf.gov.agentdns.transfers';
const policyTable = 'public:ccf.gov.agentdns.policy_identities';
const lifecycle = 'public:agentdns.lifecycle';
function fixture() {
  const tables = new Map(), actions = new Map();
  const bytes = value => Buffer.from(value).toString('hex');
  const table = name => {
    if (!tables.has(name)) tables.set(name, new Map());
    return tables.get(name);
  };
  const ccf = {
    strToBuf: value => Buffer.from(value),
    jsonCompatibleToBuf: value => Buffer.from(JSON.stringify(value)),
    bufToJsonCompatible: value => JSON.parse(Buffer.from(value).toString()),
    kv: new Proxy({}, {get: (_, name) => ({
      get: key => {
        assert.ok(name.startsWith('public:ccf.gov.'), 'governance cannot read app tables');
        return table(name).get(bytes(key));
      },
      has: key => table(name).has(bytes(key)),
      set: (key, value) => table(name).set(bytes(key), value),
      get size() { return table(name).size; },
    })}),
  };
  vm.runInNewContext(source, {ccf, actions, Action: class {
    constructor(validate, apply) { this.validate = validate; this.apply = apply; }
  }});
  return {
    invoke(name, args) { const action=actions.get(name); action.validate(args); action.apply(args); },
    read(name, key) { return ccf.bufToJsonCompatible(table(name).get(bytes(Buffer.from(key)))); },
    table,
  };
}
function transfer(key_name='old.example.test.') {
  return {key_name, endpoint:'192.0.2.53:53', zones:['example.test.'], secret_sha256:'ab'.repeat(32)};
}
function policy(id=1) {
  return {policy_id:Array(32).fill(id), release_id:'release-1', active_profiles:['azure-aci-snp'], valid_from:1, valid_until:2000000000, max_appraisal_lifetime:600, minimum_tcb:{Milan:{bootloader:1,tee:0,snp:1,microcode:1}}, approved_measurements:['ab'.repeat(48)], approved_host_data:['cd'.repeat(32)], uvm:[]};
}
function setPolicy(f, value) { f.invoke('adns_set_appraisal_policy', {zone:'example.test.',policy:value}); }

test('revocation writes permanent mirrored tombstone and preserves replacement', () => {
  const f=fixture(), old=transfer(), replacement=transfer('new.example.test.');
  replacement.secret_sha256='cd'.repeat(32);
  f.invoke('adns_set_transfer',old); f.invoke('adns_set_transfer',replacement);
  f.invoke('adns_revoke_transfer',{key_name:old.key_name});
  const key='governance/transfer/'+old.key_name;
  assert.deepEqual(f.read(transferTable,key), {...old,revoked:true});
  assert.deepEqual(f.read(lifecycle,key), {...old,revoked:true});
  assert.deepEqual(f.read(lifecycle,'governance/transfer/'+replacement.key_name),replacement);
  f.invoke('adns_revoke_transfer',{key_name:old.key_name});
  assert.throws(()=>f.invoke('adns_set_transfer',old),/permanently revoked/);
  assert.throws(()=>f.invoke('adns_set_transfer',{...old,zones:['other.test.']}),/permanently revoked/);
  assert.throws(()=>f.invoke('adns_revoke_transfer',{key_name:'missing.test.'}),/missing/);
});
test('revoked identities retain capacity and active replacement remains editable', () => {
  const f=fixture();
  for(let i=0;i<512;i++)f.invoke('adns_set_transfer',transfer('key'+i+'.test.'));
  f.invoke('adns_revoke_transfer',{key_name:'key0.test.'});
  assert.throws(()=>f.invoke('adns_set_transfer',transfer('overflow.test.')),/maximum 512/);
  f.invoke('adns_set_transfer',{...transfer('key1.test.'),zones:['other.test.']});
  assert.throws(()=>f.invoke('adns_set_transfer',{...transfer('key1.test.'),endpoint:'192.0.2.54:53'}),/new key_name/);
});
test('policy ID is stable across object ordering and exact repeats', () => {
  const f=fixture(), p=policy(); setPolicy(f,p);
  setPolicy(f,Object.fromEntries(Object.entries(p).reverse()));
  setPolicy(f,{...p,minimum_tcb:{Milan:{microcode:1,snp:1,tee:0,bootloader:1}}});
  assert.equal(f.table(policyTable).size,1);
  const ordered={...policy(2),approved_host_data:['cd'.repeat(32),'ef'.repeat(32)]};
  setPolicy(f,ordered);
  assert.throws(()=>setPolicy(f,{...ordered,approved_host_data:[...ordered.approved_host_data].reverse()}),/new policy_id/);
});
test('every trust change requires a new policy ID, including historical reuse', () => {
  const f=fixture(), p=policy(); setPolicy(f,p);
  for(const [key,value] of Object.entries({approved_host_data:['ef'.repeat(32)],approved_measurements:[],minimum_tcb:{},uvm:[{did:'changed',feed:'x',minimum_svn:2}],valid_until:1999999999,active_profiles:[],uvm_endorsement_time_policy:'approved_release'})) {
    assert.throws(()=>setPolicy(f,{...p,[key]:value}),/new policy_id/);
  }
  const next={...policy(2),approved_host_data:['ef'.repeat(32)]};setPolicy(f,next);
  assert.throws(()=>setPolicy(f,{...p,approved_host_data:next.approved_host_data}),/new policy_id/);
  setPolicy(f,p); // Explicit rollback to the exact historical policy is governed.
  assert.equal(f.table(policyTable).size,2);
});
test('policy history has bounded capacity without evicting identities', () => {
  const f=fixture();
  for(let i=1;i<=512;i++){const p=policy();p.policy_id[0]=i%256;p.policy_id[1]=Math.floor(i/256);setPolicy(f,p);}
  assert.throws(()=>setPolicy(f,policy(9)),/maximum 512/);
  setPolicy(f,policy());
});
test('policy identity rejects ambiguous numbers, Unicode and excessive structure', () => {
  const f=fixture();
  for(const p of [policy(0),{...policy(),valid_until:2**53},{...policy(),valid_from:0.5},{...policy(),valid_from:-0},{...policy(),release_id:'\ud800'},{...policy(),release_id:'x'.repeat(65536)},{...policy(),release_id:'é'.repeat(32768)}, {...policy(),extra:true}]) {
    assert.throws(()=>setPolicy(f,p));
  }
  let deep={};for(let i=0;i<10;i++)deep={deep};
  assert.throws(()=>setPolicy(f,{...policy(),minimum_tcb:deep}),/bounds/);
  assert.throws(()=>setPolicy(f,{...policy(),approved_host_data:Array(4097).fill('x')}),/bounds/);
  assert.equal(f.table(policyTable).size,0);
});

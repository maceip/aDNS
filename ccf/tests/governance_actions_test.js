// Exercise the actual application constitution actions with a write-only app
// map boundary. Real CCF transactional/governance coverage is control_smoke.py.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const crypto = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, '../governance/actions.js'), 'utf8');
const resolveSource = fs.readFileSync(path.join(__dirname, '../governance/resolve.js'), 'utf8').replace(/^export /gm, '');
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
    bufToStr: value => Buffer.from(value).toString(),
    jsonCompatibleToBuf: value => Buffer.from(JSON.stringify(value)),
    bufToJsonCompatible: value => JSON.parse(Buffer.from(value).toString()),
    crypto: {
      digest: (algorithm, data) => { assert.equal(algorithm, 'SHA-256'); return crypto.createHash('sha256').update(Buffer.from(data)).digest().buffer; },
      verifySignature: (algorithm, pem, signature, data) => {
        assert.deepStrictEqual(JSON.parse(JSON.stringify(algorithm)), {name: 'ECDSA', hash: 'SHA-256'});
        return crypto.createVerify('sha256').update(Buffer.from(data)).verify({key: pem, dsaEncoding: 'der'}, Buffer.from(signature));
      },
    },
    kv: new Proxy({}, {get: (_, name) => ({
      get: key => {
        assert.ok(name.startsWith('public:ccf.gov.'), 'governance cannot read app tables');
        return table(name).get(bytes(key));
      },
      has: key => table(name).has(bytes(key)),
      set: (key, value) => table(name).set(bytes(key), value),
      delete: key => table(name).delete(bytes(key)),
      clear: () => table(name).clear(),
      forEach: fn => table(name).forEach((v, k) => fn(v, Buffer.from(k, 'hex'))),
      get size() { return table(name).size; },
    })}),
  };
  const context = {ccf, actions, Action: class {
    constructor(validate, apply) { this.validate = validate; this.apply = apply; }
  }};
  vm.createContext(context);
  vm.runInContext(source + '\n' + resolveSource, context);
  let proposalCounter = 0;
  return {
    invoke(name, args, proposalId) { const action=actions.get(name); action.validate(args); action.apply(args, proposalId || 'proposal-test'); },
    member(id, status = 'Active') { table('public:ccf.gov.members.info').set(bytes(Buffer.from(id)), ccf.jsonCompatibleToBuf({status, member_data: {}})); },
    // Register a proposal the way CCF does (raw body + info), then run resolve() with the given votes.
    resolve(actionsList, proposer, votes, existingId) {
      const id = existingId || crypto.createHash('sha256').update('proposal-' + (++proposalCounter)).digest('hex');
      const body = JSON.stringify({actions: actionsList});
      table('public:ccf.gov.proposals').set(bytes(Buffer.from(id)), Buffer.from(body));
      table('public:ccf.gov.proposals_info').set(bytes(Buffer.from(id)), ccf.jsonCompatibleToBuf({proposer_id: proposer, state: 'Open', ballots: {}, final_votes: Object.fromEntries(votes.map(v => [v.member_id, v.vote]))}));
      const state = context.resolve(body, proposer, votes);
      const info = ccf.bufToJsonCompatible(table('public:ccf.gov.proposals_info').get(bytes(Buffer.from(id))));
      info.state = state; table('public:ccf.gov.proposals_info').set(bytes(Buffer.from(id)), ccf.jsonCompatibleToBuf(info));
      return {id, state};
    },
    read(name, key) { return ccf.bufToJsonCompatible(table(name).get(bytes(Buffer.from(key)))); },
    keys(name) { return [...table(name).keys()].map(k => Buffer.from(k, 'hex').toString()); },
    table,
  };
}
// Release authority D for tests: a P-256 key whose signatures use the fixed
// 64-byte r||s convention, exactly as a signing tool outside CCF would produce.
function authority() {
  const {privateKey, publicKey} = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
  const pem = publicKey.export({type: 'spki', format: 'pem'});
  const canonical = value => { const walk = v => v === null || typeof v === 'boolean' || typeof v === 'string' ? JSON.stringify(v) : typeof v === 'number' ? String(v) : Array.isArray(v) ? '[' + v.map(walk).join(',') + ']' : '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + walk(v[k])).join(',') + '}'; return walk(value); };
  const sign = (svn, payload) => ({did: 'did:x509:0:sha256:abc::eku:1.3.6.1.4.1.311.76.59.1.2', svn,
    signature: crypto.sign('sha256', Buffer.from(canonical({svn, payload})), {key: privateKey, dsaEncoding: 'ieee-p1363'}).toString('base64url')});
  return {record: {did: 'did:x509:0:sha256:abc::eku:1.3.6.1.4.1.311.76.59.1.2', public_key_pem: pem, svn: 0, valid_from: 0, valid_until: 4000000000}, sign};
}
function joinPolicy(svn) {
  return {svn, release_id: 'agentdns-v' + svn, measurements: ['ab'.repeat(48)], host_data: ['cd'.repeat(32)],
    uvm_endorsements: [{did: 'did:x509:0:sha256:uvm::eku:1', feed: 'ContainerPlat-AMD-UVM', svn: '104'}],
    tcb_versions: {Genoa: {boot_loader: 10, tee: 0, snp: 23, microcode: 84}}};
}
function grant() {
  return {grant_id: 'mail-owner', subject_spki_sha256: 'ab'.repeat(32), zones: ['agent.hosting.'], mailbox_domains: ['agent.hosting.'],
    service_hosts: ['mail.agent.hosting.'], roles: ['mx-edge'], address_cidrs: ['20.114.5.117/32'], ports: [25, 465, 587, 993],
    allowed_operations: ['register', 'renew', 'deregister', 'anchor'], acme_names: [], operator_names: [], operator_record_types: [],
    attested_names: ['cvm1._domainkey.agent.hosting.', '_receipt.mail.agent.hosting.'], attested_record_types: ['TXT'],
    max_lease_seconds: 86400, max_challenge_lifetime_seconds: 1800, valid_from: 0, valid_until: 4000000000, revoked: false};
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


test('owner grant accepts attested names/types and the anchor operation; mismatched attested fields are rejected', () => {
  const f = fixture();
  f.invoke('adns_set_owner_grant', {grant: grant()});
  assert.deepEqual(f.read('public:ccf.gov.agentdns.grants', 'mail-owner').attested_names, ['cvm1._domainkey.agent.hosting.', '_receipt.mail.agent.hosting.']);
  const half = grant(); half.attested_record_types = [];
  assert.throws(() => f.invoke('adns_set_owner_grant', {grant: half}), /go together/);
  const badType = grant(); badType.attested_record_types = ['SVCB'];
  assert.throws(() => f.invoke('adns_set_owner_grant', {grant: badType}), /unknown attested type/);
  const outside = grant(); outside.attested_names = ['cvm1._domainkey.other.'];
  // Rust rejects names outside granted zones; the constitution only checks syntax here.
  f.invoke('adns_set_owner_grant', {grant: outside});
});

test('node join policy needs a governed release authority, a valid D signature, and an advancing svn', () => {
  const f = fixture(), D = authority();
  assert.throws(() => f.invoke('adns_set_node_join_policy', {policy: joinPolicy(1), signature: D.sign(1, joinPolicy(1))}), /release authority not set/);
  f.invoke('adns_set_release_authority', {authority: D.record});
  const first = joinPolicy(1);
  f.invoke('adns_set_node_join_policy', {policy: first, signature: D.sign(1, first)});
  assert.deepEqual(f.keys('public:ccf.gov.nodes.snp.measurements'), ['ab'.repeat(48)]);
  assert.deepEqual(f.read('public:ccf.gov.nodes.snp.measurements', 'ab'.repeat(48)), 'AllowedToJoin');
  assert.deepEqual(f.read('public:ccf.gov.nodes.snp.uvm_endorsements', 'did:x509:0:sha256:uvm::eku:1'), {'ContainerPlat-AMD-UVM': {svn: '104'}});
  assert.deepEqual(f.read('public:ccf.gov.nodes.snp.tcb_versions', 'Genoa'), {boot_loader: 10, tee: 0, snp: 23, microcode: 84});
  const mirrored = f.read(lifecycle, 'governance/node-join-policy');
  assert.equal(mirrored.svn, 1); assert.match(mirrored.policy_sha256, /^[0-9a-f]{64}$/); assert.equal(mirrored.signed_by, D.record.did);
  assert.equal(f.read('public:ccf.gov.agentdns.release_authority', 'release-authority').svn, 1, 'authority svn ratchets to the signed svn');
  // Rollback and replay are refused.
  assert.throws(() => f.invoke('adns_set_node_join_policy', {policy: first, signature: D.sign(1, first)}), /anti-rollback/);
  const second = joinPolicy(2); second.measurements = ['ef'.repeat(48)];
  // Wrong signature (signed a different payload) fails.
  assert.throws(() => f.invoke('adns_set_node_join_policy', {policy: second, signature: D.sign(2, first)}), /signature invalid/);
  // Skipping an svn fails (must be current or current+1).
  const third = joinPolicy(3);
  assert.throws(() => f.invoke('adns_set_node_join_policy', {policy: third, signature: D.sign(3, third)}), /integer outside range/);
  f.invoke('adns_set_node_join_policy', {policy: second, signature: D.sign(2, second)});
  assert.deepEqual(f.keys('public:ccf.gov.nodes.snp.measurements'), ['ef'.repeat(48)], 'SET semantics: the retired measurement is gone');
  // A different key claiming the same DID cannot sign.
  const impostor = authority();
  assert.throws(() => f.invoke('adns_set_node_join_policy', {policy: third, signature: impostor.sign(3, third)}), /signature invalid/);
  // Authority rotation cannot lower the svn floor.
  assert.throws(() => f.invoke('adns_set_release_authority', {authority: {...impostor.record, svn: 1}}), /cannot regress/);
  f.invoke('adns_set_release_authority', {authority: {...impostor.record, svn: 2}});
  f.invoke('adns_set_node_join_policy', {policy: third, signature: impostor.sign(3, third)});
});

test('appraisal policies are unsigned before D exists and must be D-signed afterwards', () => {
  const f = fixture(), D = authority();
  setPolicy(f, policy(1));
  f.invoke('adns_set_release_authority', {authority: D.record});
  assert.throws(() => setPolicy(f, policy(2)), /requires the release authority signature/);
  const p2 = policy(2);
  assert.throws(() => f.invoke('adns_set_appraisal_policy', {zone: 'example.test.', policy: p2, signature: D.sign(1, policy(3))}), /signature invalid/);
  f.invoke('adns_set_appraisal_policy', {zone: 'example.test.', policy: p2, signature: D.sign(1, p2)});
  assert.deepEqual(f.read('public:agentdns.policies', Buffer.from([7,101,120,97,109,112,108,101,4,116,101,115,116,0]).toString()).policy_id, Array(32).fill(2));
  assert.equal(f.read('public:ccf.gov.agentdns.release_authority', 'release-authority').svn, 1);
});

test('release authority record is validated: did:x509, SPKI PEM, validity window', () => {
  const f = fixture(), D = authority();
  assert.throws(() => f.invoke('adns_set_release_authority', {authority: {...D.record, did: 'did:web:example'}}), /did:x509/);
  assert.throws(() => f.invoke('adns_set_release_authority', {authority: {...D.record, public_key_pem: 'nope'}}), /SPKI PEM/);
  assert.throws(() => f.invoke('adns_set_release_authority', {authority: {...D.record, valid_until: 0}}), /integer outside range/);
  f.invoke('adns_set_release_authority', {authority: D.record});
  assert.equal(f.read(lifecycle, 'governance/release-authority').did, D.record.did);
});


// ---- Governance: governors, weighted resolve, verdicts, trapdoor, settle ----
const A = 'a'.repeat(64), B = 'b'.repeat(64), C = 'c'.repeat(64), H = 'd'.repeat(64), N1 = 'e'.repeat(64), N2 = 'f'.repeat(64), N3 = '0'.repeat(64);
const RELEASE = [{name: 'adns_set_appraisal_policy', args: {}}];
const ROUTINE = [{name: 'adns_set_owner_grant', args: {}}];
function governed(f, members) { for (const [id, cls, rep] of members) { f.member(id); f.invoke('adns_set_governor', {member_id: id, class: cls, note: 't'}); if (rep) f.table('public:ccf.gov.agentdns.governors').set(Buffer.from(id).toString('hex'), Buffer.from(JSON.stringify({class: cls, reputation: rep, joined_via: 'x', note: 't'}))); } }

test('resolve: a single unregistered member is an agent with minimum reputation and can pass a high-impact proposal alone (bootstrap)', () => {
  const f = fixture(); f.member(A);
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}]).state, 'Accepted');
  assert.equal(f.resolve(RELEASE, A, []).state, 'Open');
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: false}]).state, 'Rejected');
});

test('resolve: high-impact needs 2/3 of reputation weight and min_agent_yes; routine needs a strict majority', () => {
  const f = fixture(); governed(f, [[A, 'agent', 3], [B, 'agent', 3], [C, 'agent', 3]]);
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}]).state, 'Open', '1/3 of weight is not enough');
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}, {member_id: B, vote: true}]).state, 'Accepted', '2/3 passes');
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}, {member_id: B, vote: false}]).state, 'Rejected', '1/3 no blocks a release');
  assert.equal(f.resolve(ROUTINE, A, [{member_id: A, vote: true}]).state, 'Open');
  assert.equal(f.resolve(ROUTINE, A, [{member_id: A, vote: true}, {member_id: B, vote: true}]).state, 'Accepted');
  assert.equal(f.resolve(ROUTINE, A, [{member_id: A, vote: false}, {member_id: B, vote: false}]).state, 'Rejected');
  f.invoke('adns_set_governance_parameters', {parameters: {min_agent_yes: 3}});
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}, {member_id: B, vote: true}]).state, 'Open', 'distinct-agent minimum');
});

test('resolve: caps stop one veteran or a flood of newcomers from deciding alone', () => {
  const f = fixture(); governed(f, [[A, 'agent', 60], [B, 'agent', 2], [C, 'agent', 2]]);
  // A has 60/64 raw weight but is capped at 34% -> cannot reach 2/3 alone.
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}]).state, 'Open');
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}, {member_id: B, vote: true}, {member_id: C, vote: true}]).state, 'Accepted');
  const g = fixture(); governed(g, [[A, 'agent', 4], [N1, 'agent', 1], [N2, 'agent', 1], [N3, 'agent', 1]]);
  // Three fresh joiners (raw 3 of 7) are capped to 20% collectively; they cannot outvote the veteran.
  assert.equal(g.resolve(ROUTINE, N1, [{member_id: N1, vote: true}, {member_id: N2, vote: true}, {member_id: N3, vote: true}]).state, 'Open');
  assert.equal(g.resolve(ROUTINE, A, [{member_id: A, vote: true}]).state, 'Accepted');
});

test('trapdoor: a human vote is decisive either way and beats agent weight', () => {
  const f = fixture(); governed(f, [[A, 'agent', 10], [B, 'agent', 10], [H, 'trapdoor', 0]]);
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}, {member_id: B, vote: true}, {member_id: H, vote: false}]).state, 'Rejected', 'veto');
  assert.equal(f.resolve(RELEASE, A, [{member_id: H, vote: true}]).state, 'Accepted', 'override');
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}, {member_id: B, vote: true}]).state, 'Accepted', 'agents alone still decide when the trapdoor is silent');
  // A trapdoor never counts as agent weight.
  assert.equal(f.resolve(ROUTINE, A, [{member_id: A, vote: true}]).state, 'Open');
});

test('verdicts: a block finding from a reputable agent holds a release open until withdrawn; approve verdicts self-accept', () => {
  const f = fixture(); governed(f, [[A, 'agent', 3], [B, 'agent', 3], [C, 'agent', 1]]);
  const target = f.resolve(RELEASE, A, []);   // Open release proposal
  // Verdict proposals resolve on the proposer's word alone.
  const verdict = [{name: 'adns_record_verdict', args: {proposal_id: target.id, verdict: 'block', checks: [{name: 'svn', passed: false, detail: 'svn did not advance'}], evidence: {source_manifest_sha256: 'ab'.repeat(32)}, rationale: 'rollback'}}];
  const v = f.resolve(verdict, B, []);
  assert.equal(v.state, 'Accepted');
  f.invoke('adns_record_verdict', verdict[0].args, v.id);
  assert.equal(f.read('public:ccf.gov.agentdns.verdicts', target.id + '/' + B).by, B);
  // Even unanimous yes cannot pass while B's finding stands.
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}, {member_id: B, vote: true}, {member_id: C, vote: true}], target.id).state, 'Open');
  // A low-reputation blocker (C, rep 1 < block_reputation 2) does not hold anything.
  f.invoke('adns_record_verdict', {...verdict[0].args, verdict: 'withdraw', checks: [], rationale: 'fixed'}, f.resolve([{name: 'adns_record_verdict', args: verdict[0].args}], B, []).id);
  assert.equal(f.resolve(RELEASE, A, [{member_id: A, vote: true}, {member_id: B, vote: true}], target.id).state, 'Accepted');
  assert.throws(() => f.invoke('adns_record_verdict', {...verdict[0].args, verdict: 'block', checks: [{name: 'x', passed: true, detail: ''}]}), /failed check/);
  // Trapdoor override passes through a finding.
  const g = fixture(); governed(g, [[A, 'agent', 3], [H, 'trapdoor', 0]]);
  const t2 = g.resolve(RELEASE, A, []);
  g.invoke('adns_record_verdict', {proposal_id: t2.id, verdict: 'block', checks: [{name: 'x', passed: false, detail: 'd'}], evidence: {}, rationale: 'r'}, g.resolve([{name: 'adns_record_verdict', args: {proposal_id: t2.id, verdict: 'block', checks: [{name: 'x', passed: false, detail: 'd'}], evidence: {}, rationale: 'r'}}], A, []).id);
  assert.equal(g.resolve(RELEASE, A, [{member_id: H, vote: true}], t2.id).state, 'Accepted');
});

test('settle: winning voters gain, losing voters lose, bounded, once; trapdoors are never scored', () => {
  const f = fixture(); governed(f, [[A, 'agent', 3], [B, 'agent', 3], [C, 'agent', 3], [H, 'trapdoor', 0]]);
  const p = f.resolve(RELEASE, A, [{member_id: A, vote: true}, {member_id: B, vote: true}, {member_id: C, vote: false}, {member_id: H, vote: true}]);
  assert.equal(p.state, 'Accepted');
  f.invoke('adns_settle', {proposal_id: p.id}, 's'.repeat(64));
  assert.equal(f.read('public:ccf.gov.agentdns.governors', A).reputation, 4);
  assert.equal(f.read('public:ccf.gov.agentdns.governors', B).reputation, 4);
  assert.equal(f.read('public:ccf.gov.agentdns.governors', C).reputation, 2);
  assert.equal(f.read('public:ccf.gov.agentdns.governors', H).reputation, 1, 'trapdoor untouched');
  assert.throws(() => f.invoke('adns_settle', {proposal_id: p.id}), /already settled/);
  const open = f.resolve(RELEASE, A, []);
  assert.throws(() => f.invoke('adns_settle', {proposal_id: open.id}), /not resolved/);
  // Floor at reputation_min.
  const g = fixture(); governed(g, [[A, 'agent', 1], [B, 'agent', 5]]);
  const q = g.resolve(ROUTINE, A, [{member_id: A, vote: true}, {member_id: B, vote: false}]);
  assert.equal(q.state, 'Rejected');
  g.invoke('adns_settle', {proposal_id: q.id}, 's'.repeat(64));
  assert.equal(g.read('public:ccf.gov.agentdns.governors', A).reputation, 1);
  assert.equal(g.read('public:ccf.gov.agentdns.governors', B).reputation, 6);
});

test('governance parameters: validated, merged, and reputation is not set by re-registering a governor', () => {
  const f = fixture(); governed(f, [[A, 'agent', 7]]);
  assert.throws(() => f.invoke('adns_set_governance_parameters', {parameters: {release_threshold: [3, 2]}}), /above one/);
  assert.throws(() => f.invoke('adns_set_governance_parameters', {parameters: {bogus: 1}}), /unknown or missing field/);
  f.invoke('adns_set_governance_parameters', {parameters: {min_agent_yes: 2, open_join: false}});
  assert.equal(f.read('public:ccf.gov.agentdns.governance', 'parameters').min_agent_yes, 2);
  assert.equal(f.read('public:ccf.gov.agentdns.governance', 'parameters').release_threshold[0], 2, 'defaults merged');
  f.invoke('adns_set_governor', {member_id: A, class: 'trapdoor', note: 'reclassified'});
  assert.equal(f.read('public:ccf.gov.agentdns.governors', A).reputation, 7, 'reclassification keeps reputation');
  assert.throws(() => f.invoke('adns_set_governor', {member_id: 'nope', class: 'agent', note: ''}), /64-hex/);
});

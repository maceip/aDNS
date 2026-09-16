// resolve(): the vote rule of the agent.hosting/agentdns governance (replaces the
// CCF sandbox "accept everything"). Reads only governance tables.
//
//  1. A proposal consisting solely of adns_record_verdict actions is a statement by
//     its proposer and is Accepted immediately (it writes only the verdict table).
//  2. A trapdoor member's vote is decisive: false = veto (Rejected), true = override
//     (Accepted). Both are ordinary ballots, visible in the ledger.
//  3. Otherwise agents decide by reputation-weighted vote. Weights are capped per
//     member and for newcomers once the consortium has three or more agents, so
//     neither one veteran nor a flood of fresh joiners can carry a decision alone.
//  4. High-impact proposals need yes >= 2/3 of total weight and at least
//     min_agent_yes distinct agents; they are Rejected once no >= 1/3. Routine
//     proposals need a strict majority.
//  5. An unwithdrawn `block` verdict from an agent with enough reputation holds a
//     high-impact proposal Open regardless of yes-weight (the finding mechanism).
export function resolve(proposal, proposerId, votes) {
  const params = adnsParams();
  const actionsIn = JSON.parse(proposal).actions.map(a => a.name);
  if (actionsIn.length > 0 && actionsIn.every(n => n === "adns_record_verdict")) return "Accepted";
  const highImpact = actionsIn.some(n => params.high_impact_actions.includes(n));
  const active = [];
  ccf.kv["public:ccf.gov.members.info"].forEach((v, k) => {
    if (ccf.bufToJsonCompatible(v).status === "Active") active.push(ccf.bufToStr(k));
  });
  const governor = id => adnsGovernorOf(id, params);
  for (const v of votes) {
    if (!active.includes(v.member_id)) continue;
    if (governor(v.member_id).class === "trapdoor") {
      if (v.vote === false) return "Rejected";
      if (v.vote === true) return "Accepted";
    }
  }
  if (highImpact) {
    let blocked = false;
    ccf.kv[adnsGovVerdicts].forEach((v, k) => {
      const key = ccf.bufToStr(k);
      if (!key.startsWith(proposalIdForVotes(votes, proposal) + "/")) return;
      const verdict = ccf.bufToJsonCompatible(v);
      if (verdict.verdict === "block" && active.includes(verdict.by) && governor(verdict.by).reputation >= params.block_reputation) blocked = true;
    });
    if (blocked) return "Open";
  }
  const agents = active.filter(id => governor(id).class === "agent");
  const rawWeight = Object.fromEntries(agents.map(id => [id, governor(id).reputation]));
  let total = Object.values(rawWeight).reduce((a, b) => a + b, 0);
  const weight = { ...rawWeight };
  if (agents.length >= 3) {
    // Per-member cap, relative to the capped total (iterate to a fixed point so a
    // dominant member cannot exceed the percentage of what is actually counted).
    for (let round = 0; round < 12; round++) {
      const subtotal = Object.values(weight).reduce((a, b) => a + b, 0);
      const cap = Math.max(1, Math.floor(subtotal * params.max_member_weight_percent / 100));
      let changed = false;
      for (const id of agents) if (weight[id] > cap) { weight[id] = cap; changed = true; }
      if (!changed) break;
    }
    // Newcomer cap: members at minimum reputation collectively.
    const newcomers = agents.filter(id => governor(id).reputation === params.reputation_min);
    const newcomerTotal = newcomers.reduce((a, id) => a + weight[id], 0);
    const subtotal = Object.values(weight).reduce((a, b) => a + b, 0);
    const newcomerCap = Math.floor(subtotal * params.newcomer_weight_cap_percent / 100);
    if (newcomerTotal > newcomerCap && newcomers.length > 0) {
      const scaled = Math.max(0, Math.floor(newcomerCap / newcomers.length));
      for (const id of newcomers) weight[id] = scaled;
    }
    total = Object.values(weight).reduce((a, b) => a + b, 0);
  }
  if (total === 0) return "Open";
  let yes = 0, no = 0, yesCount = 0;
  for (const v of votes) {
    if (!(v.member_id in weight)) continue;
    if (v.vote) { yes += weight[v.member_id]; yesCount++; } else no += weight[v.member_id];
  }
  if (highImpact) {
    const [bn, bd] = params.block_threshold, [rn, rd] = params.release_threshold;
    if (no * bd >= total * bn) return "Rejected";
    if (yes * rd >= total * rn && yesCount >= params.min_agent_yes) return "Accepted";
    return "Open";
  }
  const [n, d] = params.routine_threshold;
  if (no * d >= total * n) return "Rejected";
  if (yes * d > total * n && yesCount >= 1) return "Accepted";
  return "Open";
}
// CCF passes the proposal text, not its id, to resolve(). Verdicts are keyed by the
// target proposal id, so recover it from proposals_info: the Open proposal whose
// recorded ballots match the member ids voting here and whose text matches.
function proposalIdForVotes(votes, proposal) {
  let found = "";
  ccf.kv["public:ccf.gov.proposals"].forEach((v, k) => {
    if (found) return;
    if (ccf.bufToStr(v) === proposal) found = ccf.bufToStr(k);
  });
  return found;
}

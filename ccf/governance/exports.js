export function validate(input) {
  let proposal = JSON.parse(input);
  let errors = [];
  let position = 0;
  for (const action of proposal["actions"]) {
    const definition = actions.get(action.name);
    if (definition) {
      try {
        definition.validate(action.args);
      } catch (e) {
        errors.push(
          `${action.name} at position ${position} failed validation: ${e}\n${e.stack}`,
        );
      }
    } else {
      errors.push(`${action.name}: no such action`);
    }
    position++;
  }
  return { valid: errors.length === 0, description: errors.join(", ") };
}
export function apply(proposal, proposalId) {
  const proposed_actions = JSON.parse(proposal)["actions"];
  for (const proposed_action of proposed_actions) {
    const definition = actions.get(proposed_action.name);
    definition.apply(proposed_action.args, proposalId);
  }
}

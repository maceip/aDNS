# Constitution (composed artifact)

`constitution.js` is the composed CCF constitution this image packages, produced
by `steward/compose_constitution.py` in the **steward** repository at a tagged
commit; `constitution.sha256` is its digest and must equal what the live
service serves at `/gov/service/constitution`. The sources (actions, resolve,
exports, pinned CCF defaults), their tests, the steward agent and the governance
record live in `maceip/steward`. Do not edit `constitution.js` here; update the
steward repo, re-compose, and replace the artifact and digest together.

Live 2026-09-16: `5f28aa7c79ed2eefad95fc7151fab0faa91bf66a472517b6af6c649649c7b107`
(steward `v0.1.0`).

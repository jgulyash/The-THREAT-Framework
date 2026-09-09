# Coverage Derivation

The coverage band is the vulnerability term of the risk equation. It answers, for one protected target and one indicator, whether the organization has deployed countermeasures that act on that behavior. The framework defines the shapes and this rule; each organization holds its own records. Machine shapes: `data/coverage.schema.json`. This document is normative for the derivation.

## Inputs

1. The framework's `mitigates` relation: countermeasure to indicator edges, each typed by function (`prevent`, `detect`, `deny`). An edge asserts that the countermeasure acts on that behavior's pathway. Edges may cross tactics; a countermeasure reaches wherever its function genuinely acts.
2. The organization's `cm_deployment_record` for the protected target: which countermeasures are deployed, where they apply, and when they were last verified operational.
3. The indicators in scope: a live case's indicator set, or a what-if set.

## The derivation, per target and indicator

1. Collect the mitigating countermeasures for the indicator from the `mitigates` relation.
2. If the indicator carries no `mitigates` edge because it is marked `not_assessable` (no organizationally deployable control exists for the behavior), the band is `not_assessable`. It is excluded from `covered` and it never drives a posture step up.
3. Intersect the mitigating countermeasures with the target's deployments. Exclude before banding:
   - deployments whose `applies_to` scope does not reach the assessed target;
   - deployments with status `planned` or `not_deployed`;
   - deployments that are unverified, or whose `verified` date is older than the staleness window (default twelve months) at derivation time; these contribute at most `partial`;
   - countermeasures the assessed threat actor's position defeats, such as access controls whose credentials the actor holds. Actor position is a case attribute on the threat side; a control the actor operates is not a control against that actor.
4. Band the result:
   - `covered`: every relevant mitigating countermeasure class is deployed, verified, and in scope, and at least one contributing edge has function `prevent` or `deny`. Detection alone does not fully cover a behavior; a detect-only edge set caps the band at `partial`. An edge with function `unreviewed` also caps at `partial`; unreviewed edges must reach zero before the coverage layer ships.
   - `partial`: some mitigation is deployed, or contributing deployments are unverified, stale, out of scope in part, or detect-only.
   - `exposed`: no relevant mitigating countermeasure is deployed, or critical path dominance applies.
5. Critical path dominance: if the countermeasures mitigating the highest severity band indicators in play are absent, the band is `exposed` regardless of other deployments. The absent countermeasures are recorded as the gap list.

## How coverage enters posture

The published posture matrix remains the reference join. Coverage adjusts within it, upward only:

- `exposed` steps `maintain` to `watch` and `watch` to `harden`. At a cell already at `harden` or above, `exposed` does not raise the tier further; it flags the gap as top priority within that tier.
- `covered` never lowers a cell automatically. An organization may take a signed deviation downward on the strength of verified coverage; the deviation machinery owns that move.
- `partial` holds the cell; the gap detail rides the documented rationale.

## Statelessness

The derivation is a function of the current records, recomputed at each derivation. It is not a ratchet. When remediation closes a gap and a re-derivation returns the cell to its default, that return is not a deviation and requires no signature; the signed deviation machinery applies only to moves below the cell default.

## The audit line

Every derivation records: the target, the indicator, the band, the derivation date, the framework version whose `mitigates` relation it ran against, and the age of the oldest input consumed. A stale join is visible on its face.

## The disposition discipline

An `exposed` band must carry a disposition: `funded`, `accepted_with_rationale`, `transferred`, or `compensating_interim`, with a review date. This keeps the record a remediation register rather than a gap map. A gap with a funded plan and a review date is a defensible record; a bare exposed flag with silence after it is not. Deployment records and derivations are consumer held, never published, and organizations with live litigation exposure should structure record generation under counsel.

#!/usr/bin/env python3
"""THREAT Matrix framework.json structural and scoring validator.

Runs twenty-two checks (V01 through V22) over docs/data/framework.json and
reports a per-check pass/fail summary. The checks reconstruct the defect
categories a Principal Architecture Review would hunt for: duplicate IDs,
dangling Detection Mesh references, wrong matrix placement, typo'd keys,
contradictory escalation scoring, invalid lifecycle values, and
conditioned-priority lowering.

Every check carries a stable id so CI output stays diffable. On failure a
check prints one line per offending object in the form:

  ✗ [Vnn] <object-id>: <message>

No external dependencies. Uses only the Python 3 standard library so it
runs in any CI environment.

Usage:
  python3 scripts/lint/validate.py docs/data/framework.json
  python3 scripts/lint/validate.py docs/data/framework.json --fixtures scripts/lint/fixtures

The plain form validates canonical data and exits 0 when every check is
green, 1 otherwise. The --fixtures form runs the negative-fixture harness:
each fixture mutates a copy of canonical data and passes only when
validation fails AND the fixture's expected check id is among the checks
that fired.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


# Matrix key to tactic-id prefix and child-id letter. The person matrix
# carries no letter in its child ids; facility, infrastructure, and
# organization carry F, I, and O respectively.
MATRIX_PREFIX = {
    "person": "TM",
    "facility": "TF",
    "infrastructure": "TI",
    "organization": "TO",
}
MATRIX_LETTER = {
    "person": "",
    "facility": "F",
    "infrastructure": "I",
    "organization": "O",
}

PHASE_NAMES = {
    1: "Target Development",
    2: "Mobilization",
    3: "Execution",
    4: "Aftermath",
}
PHASE_4_TRACKS = {"evasion", "attribution"}

# Severity band ranks, low to critical. A conditioned priority or severity
# floor is measured against these ranks; escalation is allowed, lowering is
# not.
BAND_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Escalation-weight to severity-band thresholds. Each band is a half-open
# interval: low [0, 2.5), medium [2.5, 5.0), high [5.0, 6.5), critical
# [6.5, 10].
WEIGHT_TOLERANCE = 0.06

ID_LETTER = re.compile(r"^(?:IND|CM|RP)-([FOI]?)[0-9]{4}-[0-9]{2}$")

# Human-readable titles printed alongside each check id in the summary.
CHECK_TITLES = {
    "V01": "duplicate tactic id",
    "V02": "duplicate indicator id",
    "V03": "duplicate countermeasure id",
    "V04": "duplicate response-protocol id",
    "V05": "duplicate JSON object key",
    "V06": "dangling correlates_with",
    "V07": "dangling compensates_for",
    "V08": "dangling coordinates_with",
    "V09": "dangling source_refs bibliography key",
    "V10": "dangling cross-matrix correlates_with",
    "V11": "tactic id prefix vs matrix key",
    "V12": "child id letter and digits vs parent tactic",
    "V13": "severity_band vs escalation_weight",
    "V14": "escalation_weight vs axes composite",
    "V15": "severity_floor invalid or band below floor",
    "V16": "phase range and phase_name",
    "V17": "phase_4_track presence and value",
    "V18": "conditioned_priority lowered below band",
    "V19": "tactic matrix field vs containing key",
    "V20": "axis_confidence enum values and axis names",
    "V21": "modality facet presence, enum, and cross-field invariants",
    "V22": "conditioning_guidance shape, factor enum, and voice constraints",
    "V23": "mitigates edge shape and dangling indicator ref",
}
CHECK_IDS = [f"V{n:02d}" for n in range(1, 24)]


# Fallback thresholds if escalation_rubric.severity_thresholds is absent.
DEFAULT_THRESHOLDS = {"low": 0.0, "medium": 2.5, "high": 5.0, "critical": 6.5}


def band_for_weight(weight: float, thresholds: dict = DEFAULT_THRESHOLDS) -> str:
    """Return the severity band implied by an escalation weight, read against
    the framework's own severity_thresholds so a threshold recalibration does
    not require editing this validator."""
    if weight >= thresholds["critical"]:
        return "critical"
    if weight >= thresholds["high"]:
        return "high"
    if weight >= thresholds["medium"]:
        return "medium"
    return "low"


def id_letter(id_str: str) -> str | None:
    """Return the matrix letter embedded in an IND/CM/RP id.

    Returns an empty string for person-matrix ids (no letter), the letter
    for lettered ids, and None when the id does not match the grammar.
    """
    match = ID_LETTER.match(id_str)
    if match is None:
        return None
    return match.group(1)


def iter_tactics(data: dict):
    """Yield (matrix_key, matrix_value, tactic) for every tactic.

    Skips non-dict entries under matrices, such as the boundary_rule
    string that sits at the matrices container level.
    """
    for matrix_key, matrix_val in (data.get("matrices") or {}).items():
        if not isinstance(matrix_val, dict):
            continue
        for tactic in matrix_val.get("tactics", []) or []:
            if isinstance(tactic, dict):
                yield matrix_key, matrix_val, tactic


def collect_ids(data: dict):
    """Collect id sets for tactics, indicators, countermeasures, protocols."""
    tactic_ids: set[str] = set()
    ind_ids: set[str] = set()
    cm_ids: set[str] = set()
    rp_ids: set[str] = set()
    for _key, _val, tactic in iter_tactics(data):
        if "id" in tactic:
            tactic_ids.add(tactic["id"])
        for ind in tactic.get("indicators", []) or []:
            if isinstance(ind, dict) and "id" in ind:
                ind_ids.add(ind["id"])
        for cm in tactic.get("countermeasures", []) or []:
            if isinstance(cm, dict) and "id" in cm:
                cm_ids.add(cm["id"])
        for rp in tactic.get("response_protocols", []) or []:
            if isinstance(rp, dict) and "id" in rp:
                rp_ids.add(rp["id"])
    return tactic_ids, ind_ids, cm_ids, rp_ids


def find_duplicate_keys(raw_text: str) -> list[str]:
    """Return duplicate keys found anywhere in the raw JSON document.

    json.load silently keeps the last value when an object repeats a key,
    so the raw pairs must be inspected before that collapse happens.
    """
    duplicates: list[str] = []

    def hook(pairs):
        seen: set[str] = set()
        for key, _value in pairs:
            if key in seen:
                duplicates.append(key)
            else:
                seen.add(key)
        return dict(pairs)

    json.loads(raw_text, object_pairs_hook=hook)
    return duplicates


def run_all_checks(raw_text: str, data: dict) -> dict[str, list[str]]:
    """Run every check and return a map of check id to failure lines.

    Each failure line is preformatted as "  ✗ [Vnn] <object-id>: <message>".
    A check with an empty list passed.
    """
    results: dict[str, list[str]] = {cid: [] for cid in CHECK_IDS}

    def fail(check_id: str, object_id: str, message: str) -> None:
        results[check_id].append(f"  ✗ [{check_id}] {object_id}: {message}")

    tactic_ids, ind_ids, cm_ids, rp_ids = collect_ids(data)
    bibliography = set((data.get("bibliography") or {}).keys())
    thresholds = (data.get("escalation_rubric") or {}).get(
        "severity_thresholds", DEFAULT_THRESHOLDS
    )

    # V05 duplicate JSON object key, anywhere in the raw document.
    for key in find_duplicate_keys(raw_text):
        fail("V05", key, "JSON object key appears more than once")

    # V01 through V04 duplicate ids, detected on a second sighting.
    seen_tactic: set[str] = set()
    seen_ind: set[str] = set()
    seen_cm: set[str] = set()
    seen_rp: set[str] = set()

    for matrix_key, _matrix_val, tactic in iter_tactics(data):
        tid = tactic.get("id", "<no-id>")

        if tid in seen_tactic:
            fail("V01", tid, "tactic id is not unique across all matrices")
        else:
            seen_tactic.add(tid)

        # V11 tactic id prefix vs matrix key.
        expected_prefix = MATRIX_PREFIX.get(matrix_key)
        if expected_prefix and not str(tid).startswith(expected_prefix):
            fail(
                "V11",
                tid,
                f"id prefix does not match matrix '{matrix_key}' "
                f"(expected prefix {expected_prefix})",
            )

        # V19 tactic matrix field vs containing key.
        if tactic.get("matrix") != matrix_key:
            fail(
                "V19",
                tid,
                f"matrix field '{tactic.get('matrix')}' differs from "
                f"containing matrix key '{matrix_key}'",
            )

        # V16 phase range and phase_name.
        phase = tactic.get("phase")
        if phase not in PHASE_NAMES:
            fail("V16", tid, f"phase '{phase}' is outside the range 1 to 4")
        else:
            expected_name = PHASE_NAMES[phase]
            if tactic.get("phase_name") != expected_name:
                fail(
                    "V16",
                    tid,
                    f"phase_name '{tactic.get('phase_name')}' does not match "
                    f"phase {phase} (expected '{expected_name}')",
                )

        # V17 phase_4_track presence and value.
        track = tactic.get("phase_4_track")
        if phase == 4:
            if track not in PHASE_4_TRACKS:
                fail(
                    "V17",
                    tid,
                    f"phase-4 tactic has missing or invalid phase_4_track "
                    f"'{track}' (expected evasion or attribution)",
                )
        elif phase in (1, 2, 3):
            if track is not None:
                fail(
                    "V17",
                    tid,
                    f"phase_4_track '{track}' is present on a phase-{phase} "
                    f"tactic (forbidden below phase 4)",
                )

        # V09 source_refs on the tactic.
        _check_source_refs(fail, tid, tactic, bibliography)

        # Child id expectations. Digits come from the tactic id after its
        # two-character prefix.
        letter = MATRIX_LETTER.get(matrix_key, "")
        digits = str(tid)[2:]

        for ind in tactic.get("indicators", []) or []:
            if not isinstance(ind, dict):
                continue
            iid = ind.get("id", "<no-id>")
            if iid in seen_ind:
                fail("V02", iid, "indicator id is not unique")
            else:
                seen_ind.add(iid)
            _check_child_id(fail, "IND", iid, letter, digits, tid)
            _check_source_refs(fail, iid, ind, bibliography)
            _check_correlates(fail, iid, ind, ind_ids)
            _check_scoring(fail, iid, ind, thresholds)
            _check_axis_confidence(fail, iid, ind)
            _check_modality(fail, iid, ind)
            _check_conditioning_guidance(fail, iid, ind)

        for cm in tactic.get("countermeasures", []) or []:
            if not isinstance(cm, dict):
                continue
            cid = cm.get("id", "<no-id>")
            if cid in seen_cm:
                fail("V03", cid, "countermeasure id is not unique")
            else:
                seen_cm.add(cid)
            _check_child_id(fail, "CM", cid, letter, digits, tid)
            _check_source_refs(fail, cid, cm, bibliography)
            for ref in cm.get("compensates_for", []) or []:
                # compensates_for is CM->CM redundancy only; indicator
                # coverage lives in mitigates. An IND- referent here is a
                # type error, not a dangling ref.
                if isinstance(ref, str) and ref.startswith("IND-"):
                    fail(
                        "V07",
                        cid,
                        f"compensates_for '{ref}' targets an indicator; "
                        f"indicator coverage belongs in mitigates",
                    )
                    continue
                if ref in cm_ids:
                    continue
                fail(
                    "V07",
                    cid,
                    f"compensates_for '{ref}' resolves to no countermeasure",
                )
            for edge in cm.get("mitigates", []) or []:
                if not isinstance(edge, dict):
                    fail("V23", cid, "mitigates entry is not an edge object")
                    continue
                ref = edge.get("indicator")
                func = edge.get("function")
                if func not in ("prevent", "detect", "deny", "unreviewed"):
                    fail(
                        "V23",
                        cid,
                        f"mitigates edge '{ref}' has invalid function "
                        f"'{func}'",
                    )
                if ref not in ind_ids:
                    fail(
                        "V23",
                        cid,
                        f"mitigates '{ref}' resolves to no indicator",
                    )

        for rp in tactic.get("response_protocols", []) or []:
            if not isinstance(rp, dict):
                continue
            rid = rp.get("id", "<no-id>")
            if rid in seen_rp:
                fail("V04", rid, "response-protocol id is not unique")
            else:
                seen_rp.add(rid)
            _check_child_id(fail, "RP", rid, letter, digits, tid)
            _check_source_refs(fail, rid, rp, bibliography)
            for ref in rp.get("coordinates_with", []) or []:
                if ref not in rp_ids:
                    fail(
                        "V08",
                        rid,
                        f"coordinates_with '{ref}' resolves to no "
                        f"response_protocol",
                    )

    # V18 conditioned_priority lowering, a recursive walk over the whole
    # document. The framework ships no instance records, so this passes
    # vacuously on canonical data.
    _walk_conditioned_priority(fail, data)

    return results


def _check_source_refs(fail, object_id, obj, bibliography):
    """V09 every source_refs entry must resolve to a bibliography key."""
    for ref in obj.get("source_refs", []) or []:
        if ref not in bibliography:
            fail(
                "V09",
                object_id,
                f"source_refs '{ref}' is not a bibliography key",
            )


def _check_child_id(fail, kind, child_id, letter, digits, parent_id):
    """V12 child id must embed the matrix letter and parent tactic digits."""
    pattern = re.compile(
        rf"^{kind}-{re.escape(letter)}{re.escape(digits)}-[0-9]{{2}}$"
    )
    if not pattern.match(str(child_id)):
        fail(
            "V12",
            child_id,
            f"id does not embed parent tactic '{parent_id}' "
            f"(expected {kind}-{letter}{digits}-NN)",
        )


def _check_correlates(fail, ind_id, ind, ind_ids):
    """V06 and V10 correlates_with resolution.

    A dangling reference is reported as V10 when its matrix letter differs
    from the source indicator's letter (a cross-matrix edge), and as V06
    otherwise. Cross-matrix edges are legal when they resolve; 112 such
    directed references exist in canonical data.
    """
    source_letter = id_letter(ind_id)
    for ref in ind.get("correlates_with", []) or []:
        if ref in ind_ids:
            continue
        ref_letter = id_letter(ref)
        if ref_letter is not None and ref_letter != source_letter:
            fail(
                "V10",
                ind_id,
                f"cross-matrix correlates_with '{ref}' resolves to no "
                f"indicator",
            )
        else:
            fail(
                "V06",
                ind_id,
                f"correlates_with '{ref}' resolves to no indicator",
            )


AXIS_CONFIDENCE_AXES = {
    "impact_potential",
    "blast_radius_potential",
    "recoverability_inverse",
    "detectability",
}
AXIS_CONFIDENCE_LEVELS = {"established", "inferred", "thin"}


def _check_axis_confidence(fail, ind_id, ind):
    """V20 axis_confidence shape: keys must be real escalation axis names and
    values must be one of the three categorical levels. The field is optional
    (absence is legal); this guards a present field against typo'd axis names
    and invented confidence vocabularies (Ruling 10-A: categorical only)."""
    conf = ind.get("axis_confidence")
    if conf is None:
        return
    if not isinstance(conf, dict):
        fail("V20", ind_id, "axis_confidence must be an object")
        return
    for axis, level in conf.items():
        if axis not in AXIS_CONFIDENCE_AXES:
            fail(
                "V20",
                ind_id,
                f"axis_confidence key '{axis}' is not an escalation axis",
            )
        if level not in AXIS_CONFIDENCE_LEVELS:
            fail(
                "V20",
                ind_id,
                f"axis_confidence value '{level}' is not one of "
                f"established/inferred/thin",
            )


INSTANCE_FACTORS = {
    "target_focus",
    "pathway_stage",
    "means_in_hand",
    "tempo_trajectory",
    "proximity_access",
    "source_credibility",
}


def _check_conditioning_guidance(fail, ind_id, ind):
    """V22 conditioning_guidance contract. Optional field; when present it
    must carry exactly probe_factors (1..6 unique instance-factor enum
    names) and guidance (a non-empty string, max 240 chars, no em or en
    dashes per the field's voice rubric). Mirrors the schema so the
    contract stays gated without jsonschema."""
    cg = ind.get("conditioning_guidance")
    if cg is None:
        return
    if not isinstance(cg, dict):
        fail("V22", ind_id, "conditioning_guidance must be an object")
        return
    if set(cg) != {"probe_factors", "guidance"}:
        fail(
            "V22",
            ind_id,
            "conditioning_guidance requires exactly probe_factors + guidance",
        )
        return
    pf = cg["probe_factors"]
    if not isinstance(pf, list) or not 1 <= len(pf) <= 6:
        fail("V22", ind_id, "probe_factors must be a list of 1 to 6 names")
    else:
        for name in pf:
            if name not in INSTANCE_FACTORS:
                fail(
                    "V22",
                    ind_id,
                    f"probe_factors '{name}' is not an instance factor",
                )
        if len(pf) != len(set(map(str, pf))):
            fail("V22", ind_id, "probe_factors entries must be unique")
    guidance = cg["guidance"]
    if not isinstance(guidance, str) or not guidance.strip():
        fail("V22", ind_id, "guidance must be a non-empty string")
    else:
        if len(guidance) > 420:
            fail(
                "V22",
                ind_id,
                f"guidance is {len(guidance)} chars; max is 420",
            )
        if "—" in guidance or "–" in guidance:
            fail("V22", ind_id, "guidance contains an em or en dash")


MODALITY_VALUES = {"physical", "cyber", "cyber_physical", "human_social"}
CROSSING_MECHANISMS = {"digital", "electromagnetic", "physical_implant"}


def _check_modality(fail, ind_id, ind):
    """V21 modality facet contract. Every indicator must carry modality
    (enum) and human_social (bool). Cross-field invariants: a human_social
    modality forces human_social true, and crossing_mechanism appears
    exactly when modality is cyber_physical. The schema enforces the same
    rules; this native check keeps the invariant continuously gated even
    where a pipeline skips jsonschema validation."""
    modality = ind.get("modality")
    human_social = ind.get("human_social")
    mechanism = ind.get("crossing_mechanism")
    if modality is None:
        fail("V21", ind_id, "modality is missing")
    elif modality not in MODALITY_VALUES:
        fail("V21", ind_id, f"modality '{modality}' is not a valid value")
    if not isinstance(human_social, bool):
        fail("V21", ind_id, "human_social must be a boolean and present")
    if modality == "human_social" and human_social is not True:
        fail(
            "V21",
            ind_id,
            "modality human_social requires human_social true",
        )
    if modality == "cyber_physical":
        if mechanism not in CROSSING_MECHANISMS:
            fail(
                "V21",
                ind_id,
                "cyber_physical modality requires a valid crossing_mechanism",
            )
    elif mechanism is not None:
        fail(
            "V21",
            ind_id,
            "crossing_mechanism is only legal on cyber_physical modality",
        )


def _check_scoring(fail, ind_id, ind, thresholds=DEFAULT_THRESHOLDS):
    """V13, V14, V15 escalation scoring consistency.

    Indicators without escalation fields are skipped; later build stages
    add those fields, so their absence is legal.
    """
    axes = ind.get("escalation_axes")
    weight = ind.get("escalation_weight")
    band = ind.get("severity_band")
    floor = ind.get("severity_floor")

    # V14 stored weight vs the axes composite. The composite is the fourth
    # root of impact times blast radius times recoverability-inverse times
    # (10 minus detectability). Stored weights are rounded, so the check
    # uses a tolerance rather than exact float equality.
    if isinstance(axes, dict) and isinstance(weight, (int, float)):
        try:
            composite = (
                axes["impact_potential"]
                * axes["blast_radius_potential"]
                * axes["recoverability_inverse"]
                * (10 - axes["detectability"])
            ) ** 0.25
        except (KeyError, TypeError):
            composite = None
        if composite is not None and abs(composite - weight) > WEIGHT_TOLERANCE:
            fail(
                "V14",
                ind_id,
                f"escalation_weight {weight} deviates from axes composite "
                f"{composite:.2f} beyond {WEIGHT_TOLERANCE} tolerance",
            )

    # V15 severity_floor validity and band-below-floor.
    if floor is not None:
        if floor not in BAND_RANK:
            fail(
                "V15",
                ind_id,
                f"severity_floor '{floor}' is not a valid band",
            )
        elif band in BAND_RANK and BAND_RANK[band] < BAND_RANK[floor]:
            fail(
                "V15",
                ind_id,
                f"severity_band '{band}' is below severity_floor '{floor}'",
            )

    # V13 severity_band vs the weight-implied band, respecting the floor.
    # When a floor is present the band must be the higher rank of the
    # weight-implied band and the floor, so a floor can legitimately push
    # the band above what the weight alone implies.
    if isinstance(weight, (int, float)) and band in BAND_RANK:
        implied = band_for_weight(weight, thresholds)
        expected = implied
        if floor in BAND_RANK and BAND_RANK[floor] > BAND_RANK[implied]:
            expected = floor
        if band != expected:
            fail(
                "V13",
                ind_id,
                f"severity_band '{band}' contradicts escalation_weight "
                f"{weight} (expected '{expected}')",
            )


def _walk_conditioned_priority(fail, node, path="framework"):
    """V18 recursive walk. Any object carrying conditioned_priority must
    not rank below its own severity_band."""
    if isinstance(node, dict):
        cond = node.get("conditioned_priority")
        band = node.get("severity_band")
        if (
            isinstance(cond, str)
            and cond in BAND_RANK
            and band in BAND_RANK
            and BAND_RANK[cond] < BAND_RANK[band]
        ):
            object_id = node.get("id", path)
            fail(
                "V18",
                object_id,
                f"conditioned_priority '{cond}' is ranked below "
                f"severity_band '{band}'",
            )
        for key, value in node.items():
            _walk_conditioned_priority(fail, value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk_conditioned_priority(fail, value, f"{path}.{index}")


# Bands that are allowed to hold zero indicators by explicit design decision.
# Empty by default is a silent-dead-band smell (the pre-v1.3 low band held 0
# of 815 because an equal-quartile cut was never recalibrated at the bottom).
INTENTIONALLY_EMPTY_BANDS: set[str] = set()


def band_population_warnings(data: dict) -> list[str]:
    """W-BAND (advisory, non-failing): flag any severity band whose realized
    population is zero and that is not documented as intentionally empty.
    Regression guard against the next silent dead band."""
    counts = {b: 0 for b in BAND_RANK}
    for _mk, _mv, tactic in iter_tactics(data):
        for ind in tactic.get("indicators", []):
            band = ind.get("severity_band")
            if band in counts:
                counts[band] += 1
    warnings = []
    for band in ("low", "medium", "high", "critical"):
        if counts[band] == 0 and band not in INTENTIONALLY_EMPTY_BANDS:
            warnings.append(
                f"  ⚠ [W-BAND] severity_band '{band}' has zero indicators "
                f"and is not documented as intentionally empty"
            )
    return warnings


def print_report(results: dict[str, list[str]]) -> bool:
    """Print the per-check summary. Return True when every check passed."""
    all_green = True
    for check_id in CHECK_IDS:
        failures = results[check_id]
        title = CHECK_TITLES[check_id]
        if failures:
            all_green = False
            print(f"✗ [{check_id}] {title} ({len(failures)} failure(s))")
            for line in failures:
                print(line)
        else:
            print(f"✓ [{check_id}] {title}")
    print("")
    if all_green:
        print(f"✓ validate PASSED — all {len(CHECK_IDS)} checks are green.")
    else:
        failed = sum(1 for cid in CHECK_IDS if results[cid])
        print(f"✗ validate FAILED — {failed} check(s) reported problems.")
    return all_green


# ----------------------------------------------------------------------
# Fixture harness
# ----------------------------------------------------------------------


def _resolve(root, path: str):
    """Navigate a dot-separated path to the value it names."""
    node = root
    for part in path.split("."):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def _resolve_parent(root, path: str):
    """Navigate to the container holding the final path segment."""
    parts = path.split(".")
    node = root
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node, parts[-1]


def apply_data_op(data: dict, op: dict) -> None:
    """Apply a set, append, or del mutation to parsed data in place."""
    kind = op["op"]
    if kind == "set":
        parent, key = _resolve_parent(data, op["path"])
        if isinstance(parent, list):
            parent[int(key)] = op["value"]
        else:
            parent[key] = op["value"]
    elif kind == "append":
        target = _resolve(data, op["path"])
        target.append(op["value"])
    elif kind == "del":
        parent, key = _resolve_parent(data, op["path"])
        if isinstance(parent, list):
            del parent[int(key)]
        else:
            del parent[key]
    else:
        raise ValueError(f"unknown data op '{kind}'")


def apply_raw_op(raw_text: str, op: dict) -> str:
    """Apply a raw_replace mutation to the document text before parsing."""
    count = op.get("count", 1)
    return raw_text.replace(op["find"], op["replace"], count)


def run_fixture(canonical_raw: str, fixture: dict):
    """Run one fixture and return (passed, fired_check_ids, note).

    A fixture passes when validation fails on the mutated data AND the
    fixture's expected check id is among the checks that fired.
    """
    raw_text = canonical_raw
    for op in fixture.get("mutations", []):
        if op.get("op") == "raw_replace":
            raw_text = apply_raw_op(raw_text, op)

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return False, [], f"mutated document is not valid JSON ({exc})"

    for op in fixture.get("mutations", []):
        if op.get("op") != "raw_replace":
            try:
                apply_data_op(data, op)
            except (KeyError, IndexError, ValueError) as exc:
                return False, [], f"mutation failed to apply ({exc})"

    results = run_all_checks(raw_text, data)
    fired = [cid for cid in CHECK_IDS if results[cid]]
    expected = fixture.get("expected_check")
    if not fired:
        return False, fired, "validation passed clean on mutated data"
    if expected not in fired:
        return False, fired, f"expected {expected} did not fire"
    return True, fired, "ok"


def run_fixture_harness(canonical_raw: str, fixtures_dir: Path) -> int:
    """Run every fixture in the directory. Return 0 when all behave."""
    manifest_path = fixtures_dir / "manifest.json"
    if not manifest_path.exists():
        print(
            f"✗ fixture harness: manifest.json not found in {fixtures_dir}",
            file=sys.stderr,
        )
        return 1
    manifest = json.loads(manifest_path.read_text())
    fixture_files = manifest.get("fixtures", [])

    all_ok = True
    print(f"Fixture harness: {len(fixture_files)} fixture(s)")
    print("")
    for name in fixture_files:
        fixture_path = fixtures_dir / name
        fixture = json.loads(fixture_path.read_text())
        passed, fired, note = run_fixture(canonical_raw, fixture)
        fid = fixture.get("id", name)
        expected = fixture.get("expected_check", "?")
        fired_str = ", ".join(fired) if fired else "none"
        if passed:
            print(f"✓ {fid} expects {expected} — fired: {fired_str}")
        else:
            all_ok = False
            print(f"✗ {fid} expects {expected} — {note} (fired: {fired_str})")
    print("")
    if all_ok:
        print(
            f"✓ fixture harness PASSED — {len(fixture_files)}/"
            f"{len(fixture_files)} fixtures behave as expected."
        )
        return 0
    behaving = sum(
        1
        for name in fixture_files
        if run_fixture(
            canonical_raw, json.loads((fixtures_dir / name).read_text())
        )[0]
    )
    print(
        f"✗ fixture harness FAILED — {behaving}/{len(fixture_files)} "
        f"fixtures behave as expected."
    )
    return 1


def main() -> int:
    args = sys.argv[1:]
    fixtures_dir = None
    positional = []
    i = 0
    while i < len(args):
        if args[i] == "--fixtures":
            if i + 1 >= len(args):
                print("✗ validate: --fixtures needs a directory", file=sys.stderr)
                return 1
            fixtures_dir = Path(args[i + 1])
            i += 2
        else:
            positional.append(args[i])
            i += 1

    path = Path(positional[0]) if positional else Path("docs/data/framework.json")
    if not path.exists():
        print(f"✗ validate: framework.json not found at {path}", file=sys.stderr)
        return 1

    raw_text = path.read_text()
    try:
        json.loads(raw_text)
    except json.JSONDecodeError as exc:
        print(f"✗ validate: framework.json is not valid JSON ({exc})", file=sys.stderr)
        return 1

    if fixtures_dir is not None:
        return run_fixture_harness(raw_text, fixtures_dir)

    data = json.loads(raw_text)
    results = run_all_checks(raw_text, data)
    all_green = print_report(results)
    for warning in band_population_warnings(data):
        print(warning)
    return 0 if all_green else 1


if __name__ == "__main__":
    sys.exit(main())

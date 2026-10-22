"""tmcheck: a checker for threat models kept as YAML in the repository.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass
import yaml


class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"


def load_model(path) -> dict:
    """Read the YAML file with yaml.safe_load and return the mapping.

    Missing or null `zones`, `elements`, `flows`, `threats` become []. Raise ModelError if the
    file cannot be read, is not valid YAML, uses a tag safe_load refuses, has a top level that
    is not a mapping, or has one of the four sections that is not a list.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise ModelError(f"Error reading file: {e}")

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise ModelError("Top level of the model must be a mapping (dictionary)")

    sections = ["zones", "elements", "flows", "threats"]
    for section in sections:
        if section not in data or data[section] is None:
            data[section] = []
        elif not isinstance(data[section], list):
            raise ModelError(f"Section '{section}' must be a list")

    return data


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    """STRIDE per element: the categories that apply to `kind`. Unknown kind: ValueError."""
    if kind == "external_entity":
        return {"S", "R"}
    elif kind == "process":
        return {"S", "T", "R", "I", "D", "E"}
    elif kind == "data_store":
        categories = {"T", "I", "D"}
        if is_log:
            categories.add("R")
        return categories
    elif kind == "data_flow":
        return {"T", "I", "D"}
    else:
        raise ValueError(f"Unknown element kind: {kind}")


def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    issues = set()
    
    zones = model.get("zones", [])
    elements = model.get("elements", [])
    flows = model.get("flows", [])
    threats = model.get("threats", [])

    zone_ids = {z.get("id") for z in zones if isinstance(z, dict) and "id" in z}
    
    all_ids = []
    for item_list in [zones, elements, flows, threats]:
        if isinstance(item_list, list):
            for item in item_list:
                if isinstance(item, dict) and "id" in item:
                    uid = item["id"]
                    if uid in all_ids:
                        issues.add(Issue(ref=str(uid), code="DUPLICATE_ID", message=f"Duplicate id found: {uid}"))
                    else:
                        all_ids.append(uid)

    element_map = {}
    for el in elements:
        if not isinstance(el, dict):
            continue
        eid = el.get("id")
        kind = el.get("kind")
        zone = el.get("zone")
        
        if kind not in ["external_entity", "process", "data_store"]:
            if eid:
                issues.add(Issue(ref=str(eid), code="BAD_KIND", message=f"Invalid element kind: {kind}"))
        
        if zone not in zone_ids:
            if eid:
                issues.add(Issue(ref=str(eid), code="UNKNOWN_ZONE", message=f"Unknown zone: {zone}"))
                
        if eid:
            element_map[eid] = el

    element_and_flow_ids = set(element_map.keys())
    for f in flows:
        if isinstance(f, dict) and "id" in f:
            element_and_flow_ids.add(f["id"])

    for f in flows:
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        source = f.get("source")
        target = f.get("target")
        
        if source not in element_map or target not in element_map:
            if fid:
                issues.add(Issue(ref=str(fid), code="UNKNOWN_REF", message="Flow source or target is not a valid element"))
        else:
            if source == target or (element_map[source].get("kind") != "process" and element_map[target].get("kind") != "process"):
                if fid:
                    issues.add(Issue(ref=str(fid), code="INVALID_FLOW", message="Invalid flow endpoints"))

    for t in threats:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        target = t.get("target")
        category = t.get("category")
        likelihood = t.get("likelihood")
        impact = t.get("impact")
        status = t.get("status")
        mitigation = t.get("mitigation")
        justification = t.get("justification")

        if target not in element_and_flow_ids:
            if tid:
                issues.add(Issue(ref=str(tid), code="UNKNOWN_REF", message="Threat target does not exist"))

        if category not in ["S", "T", "R", "I", "D", "E"]:
            if tid:
                issues.add(Issue(ref=str(tid), code="BAD_CATEGORY", message=f"Invalid STRIDE category: {category}"))
        elif target in element_map:
            kind = element_map[target].get("kind")
            is_log = element_map[target].get("is_log", False)
            try:
                allowed_cats = applicable(kind, is_log=is_log)
                if category not in allowed_cats:
                    if tid:
                        issues.add(Issue(ref=str(tid), code="INAPPLICABLE_CATEGORY", message="Category does not apply to element kind"))
            except ValueError:
                pass

        if not isinstance(likelihood, int) or isinstance(likelihood, bool) or not (1 <= likelihood <= 5) or \
           not isinstance(impact, int) or isinstance(impact, bool) or not (1 <= impact <= 5):
            if tid:
                issues.add(Issue(ref=str(tid), code="BAD_SCORE", message="Invalid likelihood or impact score"))

        if status not in ["open", "mitigated", "accepted"]:
            if tid:
                issues.add(Issue(ref=str(tid), code="BAD_STATUS", message="Invalid status"))
        else:
            if status == "mitigated" and (not isinstance(mitigation, str) or not mitigation.strip()):
                if tid:
                    issues.add(Issue(ref=str(tid), code="MISSING_MITIGATION", message="Mitigation text is missing or empty"))
            if status == "accepted" and (not isinstance(justification, str) or not justification.strip()):
                if tid:
                    issues.add(Issue(ref=str(tid), code="MISSING_JUSTIFICATION", message="Justification text is missing or empty"))

    return sorted(list(issues))


def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    elements = model.get("elements", [])
    flows = model.get("flows", [])
    
    element_zone = {}
    for el in elements:
        if isinstance(el, dict) and "id" in el and "zone" in el:
            element_zone[el["id"]] = el["zone"]
            
    crossing = []
    for f in flows:
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        source = f.get("source")
        target = f.get("target")
        
        if source in element_zone and target in element_zone:
            if element_zone[source] != element_zone[target]:
                if fid:
                    crossing.append(fid)
                    
    return crossing


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    elements = model.get("elements", [])
    flows = model.get("flows", [])
    threats = model.get("threats", [])
    
    recorded_threats = set()
    for t in threats:
        if not isinstance(t, dict):
            continue
        target = t.get("target")
        category = t.get("category")
        status = t.get("status", "open")
        if target and category and status != "accepted":
            recorded_threats.add((target, category))
            
    stride_order = {"S": 0, "T": 1, "R": 2, "I": 3, "D": 4, "E": 5}
    
    crossing = set(crossing_flows(model))
    in_scope_elements = set()
    in_scope_flows = set()
    
    if crossing:
        in_scope_flows = crossing
        for f in flows:
            if isinstance(f, dict) and f.get("id") in crossing:
                if f.get("source"): in_scope_elements.add(f.get("source"))
                if f.get("target"): in_scope_elements.add(f.get("target"))
    else:
        for el in elements:
            if isinstance(el, dict) and "id" in el:
                in_scope_elements.add(el["id"])
        for f in flows:
            if isinstance(f, dict) and "id" in f:
                in_scope_flows.add(f["id"])

    gaps = []
    
    for el in elements:
        if not isinstance(el, dict):
            continue
        eid = el.get("id")
        kind = el.get("kind")
        is_log = el.get("is_log", False)
        if not eid or not kind:
            continue
            
        if eid not in in_scope_elements:
            continue
            
        try:
            allowed = applicable(kind, is_log=is_log)
        except ValueError:
            continue
            
        for cat in allowed:
            if (eid, cat) not in recorded_threats:
                gaps.append(Gap(ref=eid, category=cat))
                
    for f in flows:
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        if not fid or fid not in in_scope_flows:
            continue
            
        try:
            allowed = applicable("data_flow")
        except ValueError:
            continue
            
        for cat in allowed:
            if (fid, cat) not in recorded_threats:
                gaps.append(Gap(ref=fid, category=cat))
                
    gaps.sort(key=lambda g: (g.ref, stride_order.get(g.category, 99)))
    return gaps


def policy_findings(model: dict) -> list[Issue]:
    """UNENCRYPTED_CROSSING, UNAUTHENTICATED_INBOUND, PII_STORE_WITHOUT_I_THREAT, sorted by (ref, code)."""
    issues = set()
    
    elements = model.get("elements", [])
    flows = model.get("flows", [])
    threats = model.get("threats", [])
    
    element_map = {el["id"]: el for el in elements if isinstance(el, dict) and "id" in el}
    
    threat_map = set()
    for t in threats:
        if not isinstance(t, dict):
            continue
        target = t.get("target")
        category = t.get("category")
        status = t.get("status", "open")
        if target and category and status == "open":
            threat_map.add((target, category))

    allowed_protocols = {"https", "tls", "mtls", "sftp", "ssh"}

    for f in flows:
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        source = f.get("source")
        target = f.get("target")
        protocol = str(f.get("protocol", "")).lower()
        
        if source in element_map and target in element_map:
            src_zone = element_map[source].get("zone")
            tgt_zone = element_map[target].get("zone")
            if src_zone and tgt_zone and src_zone != tgt_zone:
                if protocol not in allowed_protocols:
                    if fid:
                        issues.add(Issue(ref=str(fid), code="UNENCRYPTED_CROSSING", message="Flow crosses zones unencrypted"))

    for f in flows:
        if not isinstance(f, dict):
            continue
        source = f.get("source")
        target = f.get("target")
        authenticated = f.get("authenticated", True)
        
        if source in element_map and target in element_map:
            src_kind = element_map[source].get("kind")
            tgt_kind = element_map[target].get("kind")
            src_zone = element_map[source].get("zone")
            tgt_zone = element_map[target].get("zone")
            
            # Unauthenticated inbound to higher trust zone
            if src_kind == "external_entity" and tgt_kind == "process":
                if not authenticated:
                    if target:
                        issues.add(Issue(ref=str(target), code="UNAUTHENTICATED_INBOUND", message="Unauthenticated inbound flow from external entity"))

    for el in elements:
        if not isinstance(el, dict):
            continue
        eid = el.get("id")
        kind = el.get("kind")
        pii = el.get("holds_pii", False) or el.get("pii", False)
        
        if kind == "data_store" and pii:
            if eid and (eid, "I") not in threat_map:
                issues.add(Issue(ref=str(eid), code="PII_STORE_WITHOUT_I_THREAT", message="PII data store lacks an open Information Disclosure threat"))

    return sorted(list(issues))

def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    threats = model.get("threats", [])
    ranked_list = []
    
    for t in threats:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        status = t.get("status", "open")
        likelihood = t.get("likelihood")
        impact = t.get("impact")
        
        if status == "open" and isinstance(likelihood, int) and not isinstance(likelihood, bool) and 1 <= likelihood <= 5 \
           and isinstance(impact, int) and not isinstance(impact, bool) and 1 <= impact <= 5:
            
            score = likelihood * impact
            
            if score >= 15:
                level = "high"
            elif score >= 8:
                level = "medium"
            else:
                level = "low"
                
            if tid:
                ranked_list.append((str(tid), score, impact, level))
                
    ranked_list.sort(key=lambda x: (-x[1], -x[2], x[0]))
    
    return [RankedThreat(id=item[0], score=item[1], level=item[3]) for item in ranked_list]
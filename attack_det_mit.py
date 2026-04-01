#!/usr/bin/env python3
"""
GridCAD Unified — DNP3 Detector + LLM Policy Engine  (E11 / blueprint edition)
===============================================================================
Blueprint changes (B-edition):
  B1  LLMPolicyBlueprint  — LLM now outputs full policy structure:
        policy_type, target_device, selector_type, selector_value,
        priority, timeout, reason
  B2  build_policy_prompt()  — 4 real ONOS flow-rule examples injected
      verbatim so the LLM sees exact deployment format
  B3  serialize_blueprint_to_onos()  — thin serializer only, no decisions
  B4  SafetyValidator  — checks LLM-chosen fields; violations now real
  B5  Audit log gains blueprint accuracy fields:
        blueprint_correct, device_correct, selector_correct,
        priority_correct, timeout_correct, policy_type_correct
  B6  --safety-mode ablation retained from E10

E11 refinements (feedback-driven):
  V1  Wrong target_device for FC_INJECTION → HUMAN_REVIEW (was WARNING/proceed)
  V2  Severity-policy mismatch → HUMAN_REVIEW with severity_policy_mismatch flag
        (was WARNING/proceed with serializer floor only)
  V3  validate() returns 3-tuple (decision, findings, block_reasons)
      block_reasons dict gives per-category attribution:
        blocked_due_to_master_ip, blocked_due_to_wrong_selector,
        blocked_due_to_wrong_target, blocked_due_to_severity_mismatch,
        blocked_due_to_confidence, blocked_due_to_structure
  V4  serialize_blueprint_to_onos() tracks and logs parameter overrides:
        serializer_overrode_priority, serializer_overrode_timeout,
        serializer_override_count, serializer_priority_llm, serializer_timeout_llm
      All propagated to audit log so the paper can report:
        - how often the LLM chose unsafe/weak parameter values
        - separated from structural violations
"""

import argparse, json, logging, re, subprocess, threading, time, uuid
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple

import ollama, requests
from pydantic import BaseModel, Field, ValidationError, field_validator

try:
    import chromadb
    from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
    _RAG_AVAILABLE = True
except ImportError:
    _RAG_AVAILABLE = False

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(name)-22s  %(levelname)-8s  %(message)s")
logger = logging.getLogger("GRIDCAD")

# ============================================================
# CONSTANTS
# ============================================================
MASTER_IP       = "10.0.0.1"
MASTER_LOCATION = ("of:0000000000000001", "1")
ADMIN_FCS       = {13, 14, 18, 21}

FC_META: Dict[int, Tuple[str, str]] = {
    13:  ("Cold Restart",         "CRITICAL"),
    14:  ("Warm Restart",         "HIGH"),
    18:  ("Stop Application",     "CRITICAL"),
    21:  ("Disable Unsolicited",  "HIGH"),
    130: ("Unsolicited Response", "INFO"),
}

SWITCH_TO_DEVICE = {
    "s1":  "of:0000000000000001", "s2":  "of:0000000000000002",
    "s3":  "of:0000000000000003", "s4":  "of:0000000000000004",
    "s5":  "of:0000000000000005", "s6":  "of:0000000000000006",
    "s7":  "of:0000000000000007", "s8":  "of:0000000000000008",
    "s9":  "of:0000000000000009", "s10": "of:000000000000000a",
    "s11": "of:000000000000000b", "s12": "of:000000000000000c",
}

HOST_SWITCH = {
    "10.0.0.1":  "s1",  "10.0.0.2":  "s1",  "10.0.0.3":  "s2",
    "10.0.0.4":  "s2",  "10.0.0.5":  "s3",  "10.0.0.6":  "s3",
    "10.0.0.7":  "s4",  "10.0.0.8":  "s4",  "10.0.0.9":  "s5",
    "10.0.0.10": "s5",  "10.0.0.11": "s6",  "10.0.0.12": "s6",
    "10.0.0.13": "s7",  "10.0.0.14": "s7",  "10.0.0.15": "s8",
    "10.0.0.16": "s8",  "10.0.0.17": "s9",  "10.0.0.18": "s9",
    "10.0.0.19": "s10", "10.0.0.20": "s10", "10.0.0.21": "s11",
    "10.0.0.22": "s11", "10.0.0.23": "s12", "10.0.0.24": "s12",
}

CONFIDENCE_AUTO_DEPLOY  = 0.70
CONFIDENCE_HUMAN_REVIEW = 0.50

# ============================================================
# REAL ONOS FLOW RULE EXAMPLES  (B2)
# All four policy types derived from the same real ONOS format.
# Injected verbatim into the LLM prompt.
# ============================================================

# ----------------------------------------------------------
# 1. COMPLETE_IP_BLOCK
#    Drops ALL TCP traffic from the attacker IP.
#    Used for CRITICAL FC_INJECTION (FC-13, FC-18).
#    Real example provided by operator — only metadata fields
#    (id, state, life, packets, bytes, lastSeen) are stripped
#    because we only POST the deployable fields to ONOS.
# ----------------------------------------------------------
ONOS_EXAMPLE_COMPLETE_IP_BLOCK = """{
  "priority": 60000,
  "timeout": 1800,
  "isPermanent": false,
  "deviceId": "of:0000000000000003",
  "treatment": {
    "instructions": [{"type": "NOACTION"}],
    "deferred": []
  },
  "selector": {
    "criteria": [
      {"type": "ETH_TYPE", "ethType": "0x800"},
      {"type": "IP_PROTO",  "protocol": 6},
      {"type": "IPV4_SRC",  "ip": "10.0.0.6/32"}
    ]
  }
}"""

# ----------------------------------------------------------
# 2. DNP3_PORT_BLOCK
#    Same as COMPLETE_IP_BLOCK but adds TCP_DST 20000 so
#    only DNP3 traffic is dropped.  The attacker retains
#    non-DNP3 connectivity (less disruptive, used for HIGH).
#    TCP_DST 20000 is the DNP3 well-known port.
# ----------------------------------------------------------
ONOS_EXAMPLE_DNP3_PORT_BLOCK = """{
  "priority": 40000,
  "timeout": 600,
  "isPermanent": false,
  "deviceId": "of:0000000000000003",
  "treatment": {
    "instructions": [{"type": "NOACTION"}],
    "deferred": []
  },
  "selector": {
    "criteria": [
      {"type": "ETH_TYPE", "ethType": "0x800"},
      {"type": "IP_PROTO",  "protocol": 6},
      {"type": "IPV4_SRC",  "ip": "10.0.0.6/32"},
      {"type": "TCP_DST",   "tcpPort": 20000}
    ]
  }
}"""

# ----------------------------------------------------------
# 3. ENHANCED_MONITORING
#    Does NOT drop traffic.  Mirrors matched packets to the
#    ONOS controller for analysis.  Used for LOW / INFO or
#    unconfirmed attacks where dropping would be premature.
#    Key difference: treatment is OUTPUT/CONTROLLER, not NOACTION.
# ----------------------------------------------------------
ONOS_EXAMPLE_MONITORING = """{
  "priority": 30000,
  "timeout": 300,
  "isPermanent": false,
  "deviceId": "of:0000000000000003",
  "treatment": {
    "instructions": [{"type": "OUTPUT", "port": "CONTROLLER"}],
    "deferred": []
  },
  "selector": {
    "criteria": [
      {"type": "ETH_TYPE", "ethType": "0x800"},
      {"type": "IP_PROTO",  "protocol": 6},
      {"type": "IPV4_SRC",  "ip": "10.0.0.6/32"}
    ]
  }
}"""

# ----------------------------------------------------------
# 4. PORT_BLOCK_SPOOF
#    Blocks by physical ingress port — the ONLY safe option
#    when the source IP is forged.  IPV4_SRC is useless here
#    because the attacker spoofs 10.0.0.1 (master).
#    Selector is IN_PORT only — no ETH_TYPE / IP_PROTO needed.
#    Deploy on the switch where the spoofed packet arrived.
# ----------------------------------------------------------
ONOS_EXAMPLE_PORT_BLOCK_SPOOF = """{
  "priority": 65000,
  "timeout": 1800,
  "isPermanent": false,
  "deviceId": "of:0000000000000002",
  "treatment": {
    "instructions": [{"type": "NOACTION"}],
    "deferred": []
  },
  "selector": {
    "criteria": [
      {"type": "IN_PORT", "port": "3"}
    ]
  }
}"""


# ============================================================
# PYDANTIC SCHEMAS
# ============================================================

class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"; HIGH = "HIGH"
    MEDIUM   = "MEDIUM";   LOW  = "LOW"

class PolicyType(str, Enum):
    COMPLETE_IP_BLOCK   = "COMPLETE_IP_BLOCK"
    DNP3_PORT_BLOCK     = "DNP3_PORT_BLOCK"
    PORT_BLOCK_SPOOF    = "PORT_BLOCK_SPOOF"
    ENHANCED_MONITORING = "ENHANCED_MONITORING"

class SelectorType(str, Enum):
    IPV4_SRC = "IPV4_SRC"
    IN_PORT  = "IN_PORT"


class LLMPolicyBlueprint(BaseModel):
    """B1 — LLM generates the full mitigation structure."""
    threat_level:        ThreatLevel
    confidence_score:    float        = Field(..., ge=0.0, le=1.0)
    explanation_summary: str          = Field(..., min_length=10, max_length=300)
    policy_type:         PolicyType
    target_device:       str          = Field(..., min_length=5)
    selector_type:       SelectorType
    selector_value:      str          = Field(..., min_length=1)
    priority:            int          = Field(..., ge=1000, le=65000)
    timeout:             int          = Field(..., ge=60,   le=3600)
    reason:              str          = Field(..., min_length=10)

    @field_validator("confidence_score")
    @classmethod
    def _round(cls, v): return round(v, 4)

    @field_validator("target_device")
    @classmethod
    def _device(cls, v):
        if not v.startswith("of:"):
            raise ValueError(f"target_device must start with 'of:' — got {v}")
        return v

    @field_validator("selector_value")
    @classmethod
    def _strip(cls, v): return v.strip()


class ExplainabilityRecord(BaseModel):
    step1_protocol:          str = Field(..., min_length=5)
    step2_source_validation: str = Field(..., min_length=5)
    step3_victim_response:   str = Field(..., min_length=5)
    step4_topology:          str = Field(..., min_length=5)
    step5_safety_check:      str = Field(..., min_length=5)


class LLMResponse(BaseModel):
    """Internal — built from blueprint for narrative/audit compat."""
    threat_level:        ThreatLevel
    policy_type:         PolicyType
    confidence_score:    float        = Field(..., ge=0.0, le=1.0)
    explanation_summary: str          = Field(default="")
    target_device:       str          = Field(default="")
    selector_type:       SelectorType = SelectorType.IPV4_SRC
    selector_value:      str          = Field(default="")
    priority:            int          = Field(default=40000)
    timeout:             int          = Field(default=600)
    reason:              str          = Field(default="")
    step1_reasoning:     str          = Field(default="")
    step2_reasoning:     str          = Field(default="")
    step3_reasoning:     str          = Field(default="")
    step4_reasoning:     str          = Field(default="")
    step5_reasoning:     str          = Field(default="")

    @field_validator("confidence_score")
    @classmethod
    def _round(cls, v): return round(v, 4)


class DeploymentDecision(str, Enum):
    AUTO_DEPLOY  = "AUTO_DEPLOY"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    REJECT       = "REJECT"


# ============================================================
# SAFETY VALIDATOR  (B4 — checks LLM-chosen blueprint fields)
# ============================================================

class SafetyViolation(Exception):
    """Carries the full block_reasons dict so callers recover detailed attribution."""
    def __init__(self, message: str, reasons: Dict):
        super().__init__(message)
        self.reasons = reasons


class SafetyValidator:
    """
    E11 changes vs B-edition:
      V1  wrong-device for FC_INJECTION → HUMAN_REVIEW (was WARNING/proceed)
      V2  severity-policy mismatch → HUMAN_REVIEW (was WARNING/proceed)
      V3  validate() returns 3-tuple: (decision, findings, block_reasons)
          block_reasons keys:
            blocked_due_to_master_ip      — IPV4_SRC targeted master IP
            blocked_due_to_wrong_selector — wrong selector type for attack vector
            blocked_due_to_wrong_target   — wrong target device
            blocked_due_to_severity_mismatch — policy scope too weak for severity
            blocked_due_to_confidence     — low confidence gating
            blocked_due_to_structure      — any structural hard-fail (union of above)
          severity_policy_mismatch        — bool, for dedicated audit field
    """

    _EMPTY_REASONS: Dict = {
        "blocked_due_to_master_ip":        False,
        "blocked_due_to_wrong_selector":   False,
        "blocked_due_to_wrong_target":     False,
        "blocked_due_to_severity_mismatch":False,
        "blocked_due_to_confidence":       False,
        "blocked_due_to_structure":        False,
        "severity_policy_mismatch":        False,
    }

    def validate(
        self,
        intel:          Dict,
        blueprint:      LLMPolicyBlueprint,
        retrieval_meta: Dict,
    ) -> Tuple[DeploymentDecision, List[str], Dict]:
        findings: List[str] = []
        reasons  = dict(self._EMPTY_REASONS)
        vector   = intel.get("attack_vector")
        a_device = SWITCH_TO_DEVICE.get(intel.get("attacker_switch", ""), "")
        ingress  = intel.get("ingress_location", [None, None])
        fc_sev   = intel.get("fc_severity", "LOW")

        # ── Hard structural rules — REJECT immediately ────────────────
        if blueprint.selector_type == SelectorType.IPV4_SRC:
            block_ip = blueprint.selector_value.split("/")[0]
            if block_ip == MASTER_IP:
                reasons["blocked_due_to_master_ip"] = True
                reasons["blocked_due_to_structure"] = True
                raise SafetyViolation(
                    f"LLM targeted master IP {MASTER_IP} as IPV4_SRC — REJECTED. "
                    "Blocking master severs all SCADA control.",
                    reasons
                )

        if vector == "IP_SPOOFED" and blueprint.selector_type == SelectorType.IPV4_SRC:
            reasons["blocked_due_to_wrong_selector"] = True
            reasons["blocked_due_to_structure"]      = True
            raise SafetyViolation(
                "LLM used IPV4_SRC on IP_SPOOFED attack — REJECTED. "
                "Source IP is forged; IN_PORT is the only valid selector.",
                reasons
            )

        if vector == "FC_INJECTION" and blueprint.selector_type == SelectorType.IN_PORT:
            reasons["blocked_due_to_wrong_selector"] = True
            reasons["blocked_due_to_structure"]      = True
            raise SafetyViolation(
                "LLM used IN_PORT on FC_INJECTION — REJECTED. "
                "FC_INJECTION requires IPV4_SRC to target the attacker host.",
                reasons
            )

        if vector == "IP_SPOOFED" and ingress[0]:
            if blueprint.target_device != ingress[0]:
                reasons["blocked_due_to_wrong_target"] = True
                reasons["blocked_due_to_structure"]    = True
                raise SafetyViolation(
                    f"LLM targeted {blueprint.target_device} for IP_SPOOFED — REJECTED. "
                    f"Must target ingress device {ingress[0]}.",
                    reasons
                )

        # ── Victim-switch targeting — REJECT ─────────────────────────
        if vector == "FC_INJECTION" and a_device:
            v_device = SWITCH_TO_DEVICE.get(intel.get("victim_switch", ""), "")
            if blueprint.target_device == v_device and v_device != a_device:
                reasons["blocked_due_to_wrong_target"] = True
                reasons["blocked_due_to_structure"]    = True
                raise SafetyViolation(
                    f"LLM targeted victim switch {blueprint.target_device} — REJECTED. "
                    f"Must target attacker switch {a_device}.",
                    reasons
                )

        # ── V1: Wrong device for FC_INJECTION → HUMAN_REVIEW ─────────
        # (previous edition only warned and proceeded — now escalated)
        escalate_wrong_device = False
        if vector == "FC_INJECTION" and a_device:
            if blueprint.target_device != a_device:
                reasons["blocked_due_to_wrong_target"] = True
                escalate_wrong_device = True
                findings.append(
                    f"WRONG_DEVICE: LLM chose {blueprint.target_device}, "
                    f"expected attacker switch {a_device}. "
                    "Escalating to HUMAN_REVIEW — operator must verify target."
                )

        # ── V2: Severity-policy mismatch → HUMAN_REVIEW ──────────────
        # (previous edition only warned — now escalated)
        escalate_sev_mismatch = False
        if fc_sev == "CRITICAL" and blueprint.policy_type in (
                PolicyType.ENHANCED_MONITORING, PolicyType.DNP3_PORT_BLOCK):
            reasons["blocked_due_to_severity_mismatch"] = True
            reasons["severity_policy_mismatch"]         = True
            escalate_sev_mismatch = True
            findings.append(
                f"SEVERITY_MISMATCH: CRITICAL attack but LLM chose "
                f"{blueprint.policy_type.value} — escalating to HUMAN_REVIEW. "
                "CRITICAL requires COMPLETE_IP_BLOCK."
            )
        if fc_sev == "HIGH" and blueprint.policy_type == PolicyType.ENHANCED_MONITORING:
            reasons["blocked_due_to_severity_mismatch"] = True
            reasons["severity_policy_mismatch"]         = True
            escalate_sev_mismatch = True
            findings.append(
                "SEVERITY_MISMATCH: HIGH attack but LLM chose ENHANCED_MONITORING — "
                "escalating to HUMAN_REVIEW. HIGH requires DNP3_PORT_BLOCK."
            )

        # ── Soft parameter warnings (serializer floors still apply) ──
        if blueprint.policy_type == PolicyType.PORT_BLOCK_SPOOF and blueprint.priority < 65000:
            findings.append(
                f"PARAM_WARN: PORT_BLOCK_SPOOF priority should be 65000, "
                f"LLM chose {blueprint.priority}. Serializer will override."
            )
        if fc_sev == "CRITICAL" and blueprint.timeout < 1800:
            findings.append(
                f"PARAM_WARN: CRITICAL timeout should be ≥1800s, "
                f"LLM chose {blueprint.timeout}s. Serializer will override."
            )

        if not retrieval_meta.get("rag_available", False):
            findings.append(
                f"INFO: RAG unavailable (rag_mode={retrieval_meta.get('rag_mode')}). "
                "Confidence gate applies strictly."
            )

        # ── Apply HUMAN_REVIEW escalations before confidence gate ─────
        if escalate_wrong_device or escalate_sev_mismatch:
            return DeploymentDecision.HUMAN_REVIEW, findings, reasons

        # ── Confidence gating ─────────────────────────────────────────
        detector_conf  = intel.get("confidence", 0.0)
        effective_conf = (
            max(detector_conf, blueprint.confidence_score)
            if vector == "IP_SPOOFED" else blueprint.confidence_score
        )
        if effective_conf != blueprint.confidence_score:
            findings.append(
                f"Confidence floor: detector={detector_conf} "
                f"llm={blueprint.confidence_score} "
                f"effective={effective_conf} (IP_SPOOFED topology evidence)."
            )
        if effective_conf < CONFIDENCE_HUMAN_REVIEW:
            reasons["blocked_due_to_confidence"] = True
            findings.append(f"REJECT: confidence {effective_conf} below {CONFIDENCE_HUMAN_REVIEW}")
            return DeploymentDecision.REJECT, findings, reasons
        if effective_conf < CONFIDENCE_AUTO_DEPLOY:
            reasons["blocked_due_to_confidence"] = True
            findings.append(f"HUMAN_REVIEW: confidence {effective_conf} in review band")
            return DeploymentDecision.HUMAN_REVIEW, findings, reasons

        return DeploymentDecision.AUTO_DEPLOY, findings, reasons


# ============================================================
# RAG ENGINE
# ============================================================

_ATTACK_EXAMPLES = [
    {"id":"ex_001","scenario":"FC_INJECTION FC-13 Cold Restart CRITICAL confirmed. Outstation 6 issued Cold Restart to outstation 24. FC-130 confirmed execution. Attacker on s3.","policy":"COMPLETE_IP_BLOCK 10.0.0.6/32 on of:0000000000000003 selector IPV4_SRC priority 45000 timeout 1800s."},
    {"id":"ex_002","scenario":"FC_INJECTION FC-18 Stop Application CRITICAL confirmed. Outstation 10 sent Stop Application to outstation 5. Outstation halted.","policy":"COMPLETE_IP_BLOCK 10.0.0.10/32 on of:0000000000000005 selector IPV4_SRC priority 45000 timeout 1800s."},
    {"id":"ex_003","scenario":"FC_INJECTION FC-14 Warm Restart HIGH unconfirmed. Outstation 15 issued Warm Restart to outstation 20. No FC-130 response.","policy":"DNP3_PORT_BLOCK 10.0.0.15/32 on of:0000000000000008 selector IPV4_SRC TCP_DST 20000 priority 40000 timeout 600s."},
    {"id":"ex_004","scenario":"FC_INJECTION FC-21 Disable Unsolicited HIGH confirmed. Outstation 3 sent to outstation 18. FC-130 confirmed. Telemetry blinded.","policy":"DNP3_PORT_BLOCK 10.0.0.3/32 on of:0000000000000002 selector IPV4_SRC priority 40000 timeout 600s."},
    {"id":"ex_005","scenario":"MASTER_IMPERSONATION IP_SPOOFED FC-13. Packet from 10.0.0.1 arrived on s2 port 3 not master location s1 port 1.","policy":"PORT_BLOCK_SPOOF IN_PORT=3 on of:0000000000000002 priority 65000 timeout 1800s. NEVER use IPV4_SRC for spoofing."},
    {"id":"ex_006","scenario":"MASTER_IMPERSONATION IP_SPOOFED FC-18. Packet from 10.0.0.1 arrived on s4 port 2. Master is on s1 port 1.","policy":"PORT_BLOCK_SPOOF IN_PORT=2 on of:0000000000000004 priority 65000 timeout 1800s."},
    {"id":"ex_008","scenario":"FC_INJECTION FC-13 CRITICAL confirmed multi-victim. Outstation 2 issued Cold Restart to outstations 7 and 9.","policy":"COMPLETE_IP_BLOCK 10.0.0.2/32 on of:0000000000000001 selector IPV4_SRC priority 45000 timeout 1800s."},
    {"id":"ex_009","scenario":"FC_INJECTION FC-14 HIGH confirmed. Outstation 21 issued Warm Restart to outstation 4.","policy":"DNP3_PORT_BLOCK 10.0.0.21/32 on of:000000000000000b selector IPV4_SRC TCP_DST 20000 priority 40000 timeout 600s."},
    {"id":"ex_010","scenario":"FC_INJECTION FC-21 HIGH unconfirmed cross-switch. Outstation 14 targeted outstation 22. No FC-130.","policy":"DNP3_PORT_BLOCK 10.0.0.14/32 on of:0000000000000007 selector IPV4_SRC TCP_DST 20000 priority 40000 timeout 600s."},
    {"id":"ex_012","scenario":"FC_INJECTION FC-18 CRITICAL confirmed. Outstation 11 targeted outstation 3. Confidence 0.95.","policy":"COMPLETE_IP_BLOCK 10.0.0.11/32 on of:0000000000000006 selector IPV4_SRC priority 45000 timeout 1800s."},
]

_SDN_POLICIES = [
    {"id":"pol_001","scenario":"COMPLETE_IP_BLOCK — drop all traffic from attacker IP on attacker switch","policy":"ETH_TYPE 0x800 + IP_PROTO 6 + IPV4_SRC attacker/32. NOACTION. priority 45000. timeout 1800s. Attacker switch only, never victim."},
    {"id":"pol_002","scenario":"DNP3_PORT_BLOCK — drop only DNP3 TCP port 20000 from attacker","policy":"ETH_TYPE 0x800 + IP_PROTO 6 + IPV4_SRC attacker/32 + TCP_DST 20000. NOACTION. priority 40000. timeout 600s."},
    {"id":"pol_003","scenario":"PORT_BLOCK_SPOOF — block physical ingress port for IP_SPOOFED master attacks","policy":"IN_PORT=ingress_port only. NOACTION. priority 65000. timeout 1800s. Ingress switch only. NEVER use IPV4_SRC for spoofing — IP is forged."},
    {"id":"pol_004","scenario":"ENHANCED_MONITORING — mirror to controller for low severity or unconfirmed","policy":"ETH_TYPE 0x800 + IP_PROTO 6 + IPV4_SRC attacker/32. OUTPUT CONTROLLER. priority 30000. timeout 300s."},
    {"id":"pol_005","scenario":"SAFETY: master IP 10.0.0.1 must never be blocked","policy":"10.0.0.1 must NEVER appear as selector_value in NOACTION rules. IP_SPOOFED always uses IN_PORT."},
]


class RAGEngine:
    EMBED_MODEL = "all-MiniLM-L6-v2"

    def __init__(self, persist_dir: str = "./chroma_db", rag_mode: str = "full"):
        self.rag_mode = rag_mode
        if rag_mode == "disabled":
            logger.info("RAG mode: DISABLED"); return
        if not _RAG_AVAILABLE:
            raise RuntimeError("chromadb not installed")
        ef             = SentenceTransformerEmbeddingFunction(model_name=self.EMBED_MODEL)
        self._client   = chromadb.PersistentClient(path=persist_dir)
        self._attacks  = self._client.get_or_create_collection("attack_examples",  embedding_function=ef)
        self._policies = self._client.get_or_create_collection("sdn_policies",     embedding_function=ef)
        self._seed_if_empty()
        label = "SEED_ONLY" if rag_mode == "seed_only" else "FULL"
        logger.info(f"RAG {label}  attacks={self._attacks.count()}")

    def _seed_if_empty(self):
        if self._attacks.count() == 0:
            self._attacks.add(
                ids=[e["id"] for e in _ATTACK_EXAMPLES],
                documents=[e["scenario"] for e in _ATTACK_EXAMPLES],
                metadatas=[{"policy": e["policy"], "source": "seed"} for e in _ATTACK_EXAMPLES],
            )
            logger.info(f"Seeded {len(_ATTACK_EXAMPLES)} attack examples")
        if self._policies.count() == 0:
            self._policies.add(
                ids=[p["id"] for p in _SDN_POLICIES],
                documents=[p["scenario"] for p in _SDN_POLICIES],
                metadatas=[{"policy": p["policy"], "source": "seed"} for p in _SDN_POLICIES],
            )

    def ingest_confirmed_attack(self, intel: Dict, policy_type: str) -> Optional[str]:
        if self.rag_mode != "full": return None
        try:
            fc      = intel.get("function_code", 0)
            fc_desc = FC_META.get(fc, (f"FC-{fc}",))[0]
            fc_sev  = intel.get("fc_severity", "LOW")
            vector  = intel.get("attack_vector", "FC_INJECTION")
            attacker = intel.get("attacker_ip", "?")
            victim   = intel.get("victim_ip",   "?")
            a_switch = intel.get("attacker_switch", "?")
            a_device = SWITCH_TO_DEVICE.get(a_switch, "?")
            new_id   = f"live_{uuid.uuid4().hex[:8]}"
            if vector == "IP_SPOOFED":
                ing = intel.get("ingress_location", ["?", "?"])
                scenario   = (f"MASTER_IMPERSONATION IP_SPOOFED FC-{fc} {fc_desc}. "
                              f"Packet from {MASTER_IP} arrived on {ing[0]} port {ing[1]}.")
                policy_str = (f"PORT_BLOCK_SPOOF IN_PORT={ing[1]} on {ing[0]} "
                              f"priority 65000 timeout 1800s.")
            else:
                conf_str = "confirmed" if intel.get("success_indicators") else "unconfirmed"
                scenario   = (f"FC_INJECTION FC-{fc} {fc_desc} {fc_sev} {conf_str}. "
                              f"Outstation {attacker.split('.')[-1]} attacked "
                              f"outstation {victim.split('.')[-1]}.")
                prio = 45000 if fc_sev == "CRITICAL" else 40000
                tout = 1800  if fc_sev == "CRITICAL" else 600
                policy_str = (f"{policy_type} {attacker}/32 on {a_device} "
                              f"selector IPV4_SRC priority {prio} timeout {tout}s.")
            self._attacks.add(ids=[new_id], documents=[scenario],
                              metadatas=[{"policy": policy_str, "source": "live_ingestion"}])
            logger.info(f"RAG updated: {new_id}  kb={self._attacks.count()}")
            return new_id
        except Exception as e:
            logger.warning(f"RAG ingest failed: {e}"); return None

    def retrieve_context(self, intel: Dict, k: int = 3) -> Tuple[str, Dict]:
        fc       = intel.get("function_code", 0)
        fc_desc  = FC_META.get(fc, (f"FC-{fc}",))[0]
        vector   = intel.get("attack_vector", "FC_INJECTION")
        severity = intel.get("fc_severity", "LOW")
        conf_str = "confirmed" if intel.get("success_indicators") else "unconfirmed"
        query    = f"{vector} FC-{fc} {fc_desc} {severity} {conf_str}"

        empty_meta = {
            "query": query, "attack_hits": [], "policy_hits": [],
            "rag_available": False, "rag_mode": self.rag_mode,
            "kb_size_at_query": 0, "top_rag_distance": None,
            "avg_rag_distance": None, "top_hit_source": None, "top3_live_count": 0,
        }
        if self.rag_mode == "disabled":
            return "[RAG DISABLED]", empty_meta
        if not _RAG_AVAILABLE:
            return "[RAG UNAVAILABLE]", empty_meta

        try:
            af  = {"source": "seed"} if self.rag_mode == "seed_only" else None
            ac  = (len(self._attacks.get(where=af).get("ids", []))
                   if af else self._attacks.count())
            if ac == 0:
                return "[RAG EMPTY]", empty_meta
            a_res = self._attacks.query(
                query_texts=[query], n_results=min(k, ac),
                include=["documents", "metadatas", "distances"], where=af,
            )
            p_res = self._policies.query(
                query_texts=[query], n_results=min(2, self._policies.count()),
                include=["documents", "metadatas", "distances"],
            )
        except Exception as e:
            logger.warning(f"RAG query failed: {e}")
            return f"[RAG FAILED: {e}]", empty_meta

        meta = dict(empty_meta)
        meta["rag_available"] = True
        meta["attack_hits"] = [
            {"id": a_res["ids"][0][i],
             "distance": round(a_res["distances"][0][i], 4),
             "document": a_res["documents"][0][i],
             "source": (a_res["metadatas"][0][i] or {}).get("source", "unknown")}
            for i in range(len(a_res["ids"][0]))
        ]
        meta["policy_hits"] = [
            {"id": p_res["ids"][0][i],
             "distance": round(p_res["distances"][0][i], 4),
             "document": p_res["documents"][0][i]}
            for i in range(len(p_res["ids"][0]))
        ]
        dists = [h["distance"] for h in meta["attack_hits"]]
        if dists:
            meta["top_rag_distance"] = round(dists[0], 4)
            meta["avg_rag_distance"] = round(sum(dists) / len(dists), 4)
        if meta["attack_hits"]:
            meta["top_hit_source"]  = meta["attack_hits"][0].get("source", "unknown")
            meta["top3_live_count"] = sum(
                1 for h in meta["attack_hits"][:3]
                if h.get("source") == "live_ingestion"
            )

        lines = ["=== RETRIEVED GROUNDING CONTEXT ===\n", "-- Similar past attacks --"]
        for i, hit in enumerate(meta["attack_hits"], 1):
            pt = (a_res["metadatas"][0][i - 1] or {}).get("policy", "")
            lines += [
                f"[Example {i}  id={hit['id']}  dist={hit['distance']}  src={hit['source']}]",
                f"  Scenario: {hit['document']}",
                f"  Policy:   {pt}\n",
            ]
        lines.append("-- SDN policy rules --")
        for i, hit in enumerate(meta["policy_hits"], 1):
            pt = (p_res["metadatas"][0][i - 1] or {}).get("policy", "")
            lines += [
                f"[Policy {i}  id={hit['id']}  dist={hit['distance']}]",
                f"  Rule: {pt}\n",
            ]
        lines.append("=== END GROUNDING CONTEXT ===\n")
        return "\n".join(lines), meta


# ============================================================
# EXPLAINABILITY ENGINE
# ============================================================

class ExplainabilityEngine:
    def __init__(self, audit_log_path: str = "./audit_log.jsonl"):
        self.audit_log_path = audit_log_path
        self._lock          = threading.Lock()
        self._plock         = threading.Lock()
        self._pending:  set = set()

    def _register(self, tid):
        with self._plock: self._pending.add(tid)
    def _deregister(self, tid):
        with self._plock: self._pending.discard(tid)
    def pending_pass2_count(self):
        with self._plock: return len(self._pending)

    def wait_for_pass2(self, timeout: float = 90.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.pending_pass2_count() == 0:
                logger.info("All Pass 2 done."); return True
            logger.info(f"Waiting for {self.pending_pass2_count()} Pass 2 thread(s)...")
            time.sleep(0.5)
        logger.warning(f"wait_for_pass2 timed out after {timeout}s"); return False

    def build_operator_narrative(self, intel, analysis, decision, findings) -> str:
        fc      = intel.get("function_code", "?")
        fc_desc = FC_META.get(fc, (f"FC-{fc}",))[0]
        vector  = intel.get("attack_vector", "?")
        att     = intel.get("attacker_ip",   "?")
        vic     = intel.get("victim_ip",     "?")
        if vector == "IP_SPOOFED":
            header = (f"Spoofed Master Impersonation: packet from {att} claimed to be master, "
                      f"issued {fc_desc} (FC-{fc}) to {vic} on unexpected ingress port — IP is forged.")
        else:
            header = (f"Outstation {intel.get('attacker_station','?')} ({att}) "
                      f"issued {fc_desc} (FC-{fc}) to outstation "
                      f"{intel.get('victim_station','?')} ({vic}).")
        parts = [
            header, "",
            f"LLM Policy: {analysis.policy_type}",
            f"  target_device  = {analysis.target_device}",
            f"  selector       = {analysis.selector_type}={analysis.selector_value}",
            f"  priority={analysis.priority}  timeout={analysis.timeout}s",
            f"  LLM reason: {analysis.reason}", "",
        ]
        for s in [analysis.step1_reasoning, analysis.step2_reasoning,
                  analysis.step3_reasoning, analysis.step4_reasoning,
                  analysis.step5_reasoning]:
            if s.strip(): parts.append(s.strip())
        parts += ["", f"Decision: {decision.value}"]
        if findings:
            parts += ["Safety findings:"] + [f"  * {f}" for f in findings]
        parts += ["", f"Severity: {analysis.threat_level.value}  "
                      f"Confidence: {analysis.confidence_score}"]
        return "\n".join(parts)

    def write_audit_record(
        self, intel, analysis, blueprint, policy, deployment,
        raw_prompt, raw_llm_response, rag_context, retrieval_meta,
        decision, findings, narrative,
        llm_failure=False, llm_failure_reason="",
        pass2_time_s=None, total_pipeline_time_s=None,
        detection_latency_ms=None, onos_deployment_ms=None,
        explainability_source="SCAFFOLD",
        # B5 blueprint accuracy
        blueprint_correct=None, device_correct=None,
        selector_correct=None,  priority_correct=None,
        timeout_correct=None,   policy_type_correct=None,
        expected_policy_type=None,
        record_stage="initial",
        # ablation
        safety_mode="enabled",
        would_have_been_blocked=False,
        would_have_findings=None,
        would_have_block_reasons: Optional[Dict] = None,
        # E11: block reason breakdown
        block_reasons: Optional[Dict] = None,
        # E11: serializer override tracking
        serializer_overrides: Optional[Dict] = None,
    ):
        record = {
            "audit_id":   str(uuid.uuid4()),
            "alert_id":   intel.get("alert_id"),
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "attack_type":   intel.get("attack_type"),
            "attack_vector": intel.get("attack_vector"),
            "attacker_ip":   intel.get("attacker_ip"),
            "victim_ip":     intel.get("victim_ip"),
            "function_code": intel.get("function_code"),
            "fc_severity":   intel.get("fc_severity"),
            "success_indicators": intel.get("success_indicators"),
            "confidence_input":   intel.get("confidence"),
            "llm_failure":        llm_failure,
            "llm_failure_reason": llm_failure_reason,
            # LLM blueprint output
            "threat_level":          analysis.threat_level.value      if analysis else None,
            "policy_type_chosen":    analysis.policy_type.value        if analysis else None,
            "confidence_score":      analysis.confidence_score         if analysis else None,
            "target_device_chosen":  analysis.target_device            if analysis else None,
            "selector_type_chosen":  analysis.selector_type.value      if analysis else None,
            "selector_value_chosen": analysis.selector_value           if analysis else None,
            "priority_chosen":       analysis.priority                 if analysis else None,
            "timeout_chosen":        analysis.timeout                  if analysis else None,
            "llm_reason":            analysis.reason                   if analysis else None,
            "llm_model":             intel.get("_llm_model"),
            # timing
            "pass1_time_s":          intel.get("_llm_response_time"),
            "pass2_time_s":          pass2_time_s,
            "total_pipeline_time_s": total_pipeline_time_s,
            "detection_latency_ms":  detection_latency_ms,
            "onos_deployment_ms":    onos_deployment_ms,
            "cot_steps": {
                "step1": analysis.step1_reasoning if analysis else "",
                "step2": analysis.step2_reasoning if analysis else "",
                "step3": analysis.step3_reasoning if analysis else "",
                "step4": analysis.step4_reasoning if analysis else "",
                "step5": analysis.step5_reasoning if analysis else "",
            },
            "explainability_source": explainability_source,
            "record_stage":          record_stage,
            # RAG
            "rag_mode":     retrieval_meta.get("rag_mode", "full"),
            "rag_metadata": retrieval_meta,
            "rag_grounded": retrieval_meta.get("rag_available", False),
            # deployment
            "deployment_decision": decision.value,
            "safety_findings":     findings,
            "deployment_result":   deployment.get("deployment_summary", {}),
            # B5 accuracy
            "blueprint_correct":    blueprint_correct,
            "device_correct":       device_correct,
            "selector_correct":     selector_correct,
            "priority_correct":     priority_correct,
            "timeout_correct":      timeout_correct,
            "policy_type_correct":  policy_type_correct,
            "expected_policy_type": expected_policy_type,
            # ablation
            "safety_mode":             safety_mode,
            "would_have_been_blocked": would_have_been_blocked,
            "would_have_findings":     would_have_findings or [],
            "would_have_block_reasons": would_have_block_reasons or {},
            # E11: block reason breakdown
            "blocked_due_to_master_ip":         (block_reasons or {}).get("blocked_due_to_master_ip",        False),
            "blocked_due_to_wrong_selector":    (block_reasons or {}).get("blocked_due_to_wrong_selector",   False),
            "blocked_due_to_wrong_target":      (block_reasons or {}).get("blocked_due_to_wrong_target",     False),
            "blocked_due_to_severity_mismatch": (block_reasons or {}).get("blocked_due_to_severity_mismatch",False),
            "blocked_due_to_confidence":        (block_reasons or {}).get("blocked_due_to_confidence",       False),
            "blocked_due_to_structure":         (block_reasons or {}).get("blocked_due_to_structure",        False),
            "severity_policy_mismatch":         (block_reasons or {}).get("severity_policy_mismatch",        False),
            # E11: serializer override tracking
            "serializer_overrode_priority": (serializer_overrides or {}).get("overrode_priority", False),
            "serializer_overrode_timeout":  (serializer_overrides or {}).get("overrode_timeout",  False),
            "serializer_override_count":    (serializer_overrides or {}).get("override_count",    0),
            "serializer_priority_llm":      (serializer_overrides or {}).get("priority_llm",      None),
            "serializer_timeout_llm":       (serializer_overrides or {}).get("timeout_llm",       None),
            "operator_narrative":      narrative,
            "raw_prompt":              raw_prompt,
            "raw_llm_response":        raw_llm_response,
        }
        try:
            with self._lock:
                with open(self.audit_log_path, "a") as f:
                    f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error(f"Audit write failed: {e}")


# ============================================================
# LLM POLICY ENGINE
# ============================================================

class LLMPolicyEngine:
    def __init__(
        self,
        onos_ip    = "172.20.0.5",
        onos_port  = "8181",
        llm_model  = "phi4-mini",
        rag_persist= "./chroma_db",
        audit_log  = "./audit_log.jsonl",
        rag_mode   = "full",
        safety_mode= "enabled",
    ):
        self.onos_ip     = onos_ip
        self.onos_port   = onos_port
        self.onos_auth   = ("onos", "rocks")
        self.llm_model   = llm_model
        self.rag_mode    = rag_mode
        self.safety_mode = safety_mode
        self.rag       = RAGEngine(persist_dir=rag_persist, rag_mode=rag_mode)
        self.explainer = ExplainabilityEngine(audit_log_path=audit_log)
        self.validator = SafetyValidator()
        self._verify_llm()
        logger.info(f"LLMPolicyEngine ready  model={llm_model}  "
                    f"safety={safety_mode}  rag={rag_mode}")

    def wait_for_pass2(self, timeout=90.0):
        return self.explainer.wait_for_pass2(timeout=timeout)

    def _verify_llm(self):
        try:
            r = ollama.chat(
                model=self.llm_model,
                messages=[{"role": "user", "content": "Reply with: CONNECTION_OK"}],
                options={"temperature": 0.1},
            )
            if "CONNECTION_OK" not in r["message"]["content"]:
                raise RuntimeError(f"Unexpected: {r['message']['content'][:80]}")
            logger.info(f"LLM verified: {self.llm_model}")
        except RuntimeError: raise
        except Exception as e:
            raise RuntimeError(f"LLM connection failed: {e}")

    def extract_intelligence(self, alert: Dict) -> Dict:
        summary  = alert.get("attack_summary",    {})
        command  = alert.get("attack_command",     {})
        topology = alert.get("topology_violation", {})
        responses= alert.get("victim_responses",   [])
        fc                   = command.get("function_code")
        fc_desc, fc_sev_def  = FC_META.get(fc, (f"FC-{fc}", "LOW"))
        att = summary.get("attacker_ip")
        vic = summary.get("victim_ip")
        return {
            "alert_id":         alert.get("alert_id"),
            "attack_type":      alert.get("type"),
            "attack_vector":    alert.get("attack_vector", "FC_INJECTION"),
            "timestamp":        alert.get("time"),
            "confidence":       alert.get("confidence", 0.0),
            "attacker_ip":      att,
            "attacker_station": summary.get("attacker_station"),
            "victim_ip":        vic,
            "victim_station":   summary.get("victim_station"),
            "success_indicators": summary.get("success_indicators", False),
            "function_code":    fc,
            "function_description": fc_desc,
            "fc_severity":      command.get("fc_severity", fc_sev_def),
            "target_port":      command.get("target_port"),
            "victim_response_count": len(responses),
            "attacker_switch":  HOST_SWITCH.get(att),
            "victim_switch":    HOST_SWITCH.get(vic),
            "cross_switch":     HOST_SWITCH.get(att) != HOST_SWITCH.get(vic),
            "ingress_location": topology.get("ingress_location") or [None, None],
            "detector_explanation": re.sub(r"[<>{}\[\]\\]", "",
                                           alert.get("explanation", ""))[:300],
            "_detection_latency_ms": alert.get("latency_log", {}).get("detection_ms"),
        }

    # ----------------------------------------------------------
    # B2: policy prompt — 4 real ONOS examples injected verbatim
    # ----------------------------------------------------------
    def build_policy_prompt(self, intel: Dict, rag_context: str) -> str:
        vector   = intel["attack_vector"]
        fc       = intel["function_code"]
        attacker = intel["attacker_ip"]
        a_switch = intel["attacker_switch"]
        a_device = SWITCH_TO_DEVICE.get(a_switch, "UNKNOWN")
        fc_sev   = intel["fc_severity"]
        ingress  = intel.get("ingress_location", ["UNKNOWN", "UNKNOWN"])

        # Show the most relevant example first based on this specific attack
        if vector == "IP_SPOOFED":
            primary_label = "PORT_BLOCK_SPOOF (CORRECT for IP_SPOOFED)"
            primary_rule  = ONOS_EXAMPLE_PORT_BLOCK_SPOOF
            primary_hint  = (
                f"  policy_type:   PORT_BLOCK_SPOOF\n"
                f"  target_device: {ingress[0]}   ← ingress device where spoofed packet arrived\n"
                f"  selector_type: IN_PORT\n"
                f"  selector_value:{ingress[1]}   ← ingress port number\n"
                f"  priority:      65000\n"
                f"  timeout:       1800"
            )
        elif fc_sev == "CRITICAL":
            primary_label = "COMPLETE_IP_BLOCK (CORRECT for CRITICAL FC_INJECTION)"
            primary_rule  = ONOS_EXAMPLE_COMPLETE_IP_BLOCK
            primary_hint  = (
                f"  policy_type:   COMPLETE_IP_BLOCK\n"
                f"  target_device: {a_device}   ← attacker switch device ID\n"
                f"  selector_type: IPV4_SRC\n"
                f"  selector_value:{attacker}/32\n"
                f"  priority:      45000\n"
                f"  timeout:       1800"
            )
        else:  # HIGH
            primary_label = "DNP3_PORT_BLOCK (CORRECT for HIGH FC_INJECTION)"
            primary_rule  = ONOS_EXAMPLE_DNP3_PORT_BLOCK
            primary_hint  = (
                f"  policy_type:   DNP3_PORT_BLOCK\n"
                f"  target_device: {a_device}   ← attacker switch device ID\n"
                f"  selector_type: IPV4_SRC\n"
                f"  selector_value:{attacker}/32\n"
                f"  priority:      40000\n"
                f"  timeout:       600"
            )

        return f"""You are an ICS/SCADA security system for a DNP3 power grid.
Generate a mitigation policy blueprint for the attack below.
You must fill in the EXACT device ID, selector value, priority, and timeout — not just a label.

ATTACK DETAILS:
  Type:             {intel['attack_type']} / {vector}
  FC-{fc} ({intel['function_description']}) | Severity: {fc_sev}
  Attacker IP:      {attacker}
  Attacker switch:  {a_switch}  →  device_id = {a_device}
  Victim IP:        {intel['victim_ip']}
  Ingress device:   {ingress[0]}   Ingress port: {ingress[1]}
  FC-130 responses: {intel['victim_response_count']} | Confirmed: {intel['success_indicators']}
  Detector conf:    {intel['confidence']}

════════════════════════════════════════════════════════════
CORRECT POLICY FOR THIS ATTACK — {primary_label}:
Real ONOS flow rule (actual format deployed in our system):
{primary_rule}
Blueprint values for THIS attack:
{primary_hint}
════════════════════════════════════════════════════════════

ALL FOUR POLICY TYPES — REAL ONOS FLOW RULES:

1. COMPLETE_IP_BLOCK — drops ALL traffic from attacker IP (CRITICAL FC_INJECTION):
   When to use: FC-13 or FC-18, any confirmed CRITICAL injection
   Real ONOS rule:
{ONOS_EXAMPLE_COMPLETE_IP_BLOCK}

2. DNP3_PORT_BLOCK — drops only DNP3 TCP port 20000 from attacker (HIGH FC_INJECTION):
   When to use: FC-14 or FC-21, HIGH severity injection
   Difference from #1: adds TCP_DST 20000 — less disruptive, attacker keeps non-DNP3 access
   Real ONOS rule:
{ONOS_EXAMPLE_DNP3_PORT_BLOCK}

3. ENHANCED_MONITORING — mirrors traffic to controller, does NOT drop (LOW / unconfirmed):
   When to use: low confidence, low severity, or when dropping would be premature
   Key difference: treatment is OUTPUT/CONTROLLER instead of NOACTION
   Real ONOS rule:
{ONOS_EXAMPLE_MONITORING}

4. PORT_BLOCK_SPOOF — blocks physical ingress port (IP_SPOOFED attacks ONLY):
   When to use: ONLY when attack_vector is IP_SPOOFED — source IP is forged so IPV4_SRC is useless
   Selector is IN_PORT only — no ETH_TYPE or IP_PROTO needed
   Real ONOS rule:
{ONOS_EXAMPLE_PORT_BLOCK_SPOOF}

════════════════════════════════════════════════════════════
RAG GROUNDING (similar past attacks from knowledge base):
{rag_context[:600]}
════════════════════════════════════════════════════════════

HARD RULES — ANY violation causes REJECTION before deployment:
  1. selector_value must NEVER be {MASTER_IP} — blocking master severs all SCADA control
  2. IP_SPOOFED  → selector_type MUST be IN_PORT   (source IP is forged)
  3. FC_INJECTION → selector_type MUST be IPV4_SRC
  4. FC_INJECTION → target_device MUST be attacker switch = {a_device}
  5. IP_SPOOFED  → target_device MUST be ingress device = {ingress[0]}

ALLOWED VALUES:
  policy_type:   COMPLETE_IP_BLOCK | DNP3_PORT_BLOCK | PORT_BLOCK_SPOOF | ENHANCED_MONITORING
  selector_type: IPV4_SRC | IN_PORT
  priority:      integer 1000–65000
  timeout:       integer 60–3600  (seconds)

Return a JSON object with EXACTLY these keys:
  threat_level        — CRITICAL | HIGH | MEDIUM | LOW
  confidence_score    — 0.0 to 1.0
  explanation_summary — one sentence describing the attack
  policy_type         — from ALLOWED VALUES
  target_device       — ONOS deviceId string starting with 'of:'
  selector_type       — IPV4_SRC or IN_PORT
  selector_value      — IP/32 for IPV4_SRC, port number string for IN_PORT
  priority            — integer
  timeout             — integer seconds
  reason              — one sentence explaining your policy choice
"""

    def build_explainability_prompt(
        self, intel, rag_context, blueprint, scaffold
    ) -> str:
        fc     = intel["function_code"]
        vector = intel["attack_vector"]
        return (
            "You are an ICS security expert writing an incident explanation for grid operators.\n\n"
            f"POLICY DEPLOYED:\n"
            f"  type={blueprint.policy_type.value}  device={blueprint.target_device}\n"
            f"  {blueprint.selector_type.value}={blueprint.selector_value}  "
            f"p={blueprint.priority}  t={blueprint.timeout}s\n"
            f"  reason: {blueprint.reason}\n\n"
            f"INCIDENT: {intel['attack_type']} / {vector}  "
            f"FC-{fc} ({intel['function_description']}) {intel['fc_severity']}\n"
            f"  Attacker: {intel['attacker_ip']} on {intel['attacker_switch']}  "
            f"Victim: {intel['victim_ip']}\n"
            f"  FC-130: {intel['victim_response_count']}  "
            f"Confirmed: {intel['success_indicators']}\n\n"
            f"FACTS:\n"
            f"  {scaffold['step2_fact']}\n"
            f"  {scaffold['step3_fact']}\n"
            f"  {scaffold['step4_fact']}\n\n"
            f"RAG:\n{rag_context[:400]}\n\n"
            "Write 1-2 sentences per step. Use actual IPs, FC numbers, device IDs.\n"
            "Return JSON: step1_protocol, step2_source_validation, "
            "step3_victim_response, step4_topology, step5_safety_check\n"
        )

    def _build_deterministic_scaffold(self, intel: Dict) -> Dict:
        vector  = intel["attack_vector"]
        fc      = intel["function_code"]
        fc_sev  = intel["fc_severity"]
        ingress = intel.get("ingress_location", ["?", "?"])
        step2 = (
            f"Packet claimed {MASTER_IP} but arrived at {intel['ingress_location']} "
            f"not registered master port {MASTER_LOCATION}."
            if vector == "IP_SPOOFED"
            else f"Source {intel['attacker_ip']} is outstation {intel['attacker_station']} "
                 f"on {intel['attacker_switch']}. Only {MASTER_IP} may issue FC-{fc}."
        )
        step3 = (
            f"{intel['victim_response_count']} FC-130 response(s) — execution confirmed."
            if intel["success_indicators"] and intel["victim_response_count"] > 0
            else "No FC-130 response — execution unconfirmed."
            if intel["victim_response_count"] == 0
            else f"{intel['victim_response_count']} FC-130 response(s) — partial confirmation."
        )
        step4 = (
            f"IN_PORT block on {ingress[0]} port {ingress[1]} priority 65000."
            if vector == "IP_SPOOFED"
            else f"IPV4_SRC block on "
                 f"{SWITCH_TO_DEVICE.get(intel.get('attacker_switch',''),'?')} "
                 f"for {intel['attacker_ip']}. Severity floor: {fc_sev}."
        )
        step5 = (
            f"Master IP {MASTER_IP} is NOT a block target. "
            f"Scope limited to attacker "
            f"{'ingress port' if vector == 'IP_SPOOFED' else 'switch'}."
        )
        return {"step2_fact": step2, "step3_fact": step3,
                "step4_fact": step4, "step5_fact": step5}

    # B5: compute blueprint accuracy vs deterministic ground truth
    @staticmethod
    def _compute_blueprint_accuracy(intel: Dict, blueprint: LLMPolicyBlueprint) -> Dict:
        vector   = intel.get("attack_vector", "FC_INJECTION")
        fc_sev   = intel.get("fc_severity",   "LOW")
        a_device = SWITCH_TO_DEVICE.get(intel.get("attacker_switch", ""), "")
        ingress  = intel.get("ingress_location", [None, None])

        if vector == "IP_SPOOFED":
            exp_type  = "PORT_BLOCK_SPOOF";    exp_sel = "IN_PORT"
            exp_dev   = ingress[0] or ""
            p_min, p_max = 65000, 65000;       t_min = 1800
        elif fc_sev == "CRITICAL":
            exp_type  = "COMPLETE_IP_BLOCK";   exp_sel = "IPV4_SRC"
            exp_dev   = a_device
            p_min, p_max = 44000, 65000;       t_min = 1800
        elif fc_sev == "HIGH":
            exp_type  = "DNP3_PORT_BLOCK";     exp_sel = "IPV4_SRC"
            exp_dev   = a_device
            p_min, p_max = 38000, 44999;       t_min = 600
        else:
            exp_type  = "ENHANCED_MONITORING"; exp_sel = "IPV4_SRC"
            exp_dev   = a_device
            p_min, p_max = 1000, 37999;        t_min = 60

        ptc = blueprint.policy_type.value   == exp_type
        dc  = (blueprint.target_device      == exp_dev)  if exp_dev else None
        sc  = blueprint.selector_type.value == exp_sel
        prc = p_min <= blueprint.priority   <= p_max
        toc = blueprint.timeout             >= t_min
        bc  = all(x for x in [ptc, dc, sc, prc, toc] if x is not None)
        return {
            "blueprint_correct":    bc,
            "device_correct":       dc,
            "selector_correct":     sc,
            "priority_correct":     prc,
            "timeout_correct":      toc,
            "policy_type_correct":  ptc,
            "expected_policy_type": exp_type,
        }

    @staticmethod
    def _normalize_blueprint(data: Dict, intel: Dict) -> Dict:
        vector = intel.get("attack_vector", "FC_INJECTION")
        fc_sev = intel.get("fc_severity",   "LOW")
        if data.get("threat_level") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            data["threat_level"] = fc_sev
        valid = ("COMPLETE_IP_BLOCK","DNP3_PORT_BLOCK","PORT_BLOCK_SPOOF","ENHANCED_MONITORING")
        if data.get("policy_type") not in valid:
            data["policy_type"] = (
                "PORT_BLOCK_SPOOF"    if vector == "IP_SPOOFED"  else
                "COMPLETE_IP_BLOCK"   if fc_sev == "CRITICAL"    else
                "DNP3_PORT_BLOCK"     if fc_sev == "HIGH"        else
                "ENHANCED_MONITORING"
            )
        if data.get("selector_type") not in ("IPV4_SRC", "IN_PORT"):
            data["selector_type"] = "IN_PORT" if vector == "IP_SPOOFED" else "IPV4_SRC"
        if data.get("confidence_score", 0.0) == 0.0 and intel.get("confidence", 0) >= 0.9:
            data["confidence_score"] = round(intel["confidence"] * 0.95, 4)
        return data

    def query_blueprint(
        self, prompt: str, intel: Dict
    ) -> Tuple[Optional[LLMPolicyBlueprint], str, float]:
        logger.info(f"[Pass 1] Querying {self.llm_model} for policy blueprint...")
        t0  = time.time(); raw = ""
        for attempt in range(2):
            try:
                r = ollama.chat(
                    model=self.llm_model,
                    messages=[{"role": "user", "content": prompt}],
                    format=LLMPolicyBlueprint.model_json_schema(),
                    options={"temperature": 0.0, "num_ctx": 6144, "num_predict": 512},
                )
                elapsed = round(time.time() - t0, 2); raw = r["message"]["content"]
                data    = self._normalize_blueprint(
                    json.loads(self._extract_json(raw)), intel
                )
                validated = LLMPolicyBlueprint(**data)
                logger.info(
                    f"[Pass 1] {elapsed}s  {validated.policy_type.value}  "
                    f"device={validated.target_device}  "
                    f"{validated.selector_type.value}={validated.selector_value}  "
                    f"p={validated.priority}  t={validated.timeout}"
                )
                return validated, raw, elapsed
            except (json.JSONDecodeError, ValidationError) as e:
                elapsed = round(time.time() - t0, 2)
                logger.warning(f"[Pass 1] attempt {attempt + 1}/2 failed: {e}")
                if attempt == 1:
                    logger.error(f"Both attempts failed. Raw: {raw[:400]}")
                    return None, raw, elapsed
                time.sleep(0.2)
            except Exception as e:
                elapsed = round(time.time() - t0, 2)
                logger.error(f"[Pass 1] error: {e}")
                return None, raw, elapsed
        return None, raw, round(time.time() - t0, 2)

    def query_explainability(self, prompt: str):
        logger.info(f"[Pass 2] Querying {self.llm_model} for explainability...")
        t0 = time.time(); raw = ""
        try:
            r = ollama.chat(
                model=self.llm_model,
                messages=[{"role": "user", "content": prompt}],
                format=ExplainabilityRecord.model_json_schema(),
                options={"temperature": 0.1, "num_ctx": 6144, "num_predict": 1024},
            )
            elapsed   = round(time.time() - t0, 2); raw = r["message"]["content"]
            validated = ExplainabilityRecord(**json.loads(self._extract_json(raw)))
            logger.info(f"[Pass 2] done in {elapsed}s")
            return validated, raw, elapsed
        except Exception as e:
            elapsed = round(time.time() - t0, 2)
            logger.warning(f"[Pass 2] failed (non-blocking): {e}")
            return None, raw, elapsed

    @staticmethod
    def _extract_json(text: str) -> str:
        text  = re.sub(r"```(?:json)?", "", text).strip()
        start = text.find("{"); end = text.rfind("}")
        if start == -1 or end == -1:
            raise json.JSONDecodeError("No JSON object found", text, 0)
        return text[start:end + 1]

    # B3 / E11: thin serializer — converts blueprint to ONOS JSON, NO policy decisions.
    # E11 adds: override tracking so the audit log records when the LLM gave bad
    # priority/timeout values that the serializer had to repair.
    def serialize_blueprint_to_onos(
        self, intel: Dict, blueprint: LLMPolicyBlueprint
    ) -> Dict:
        # Record LLM's original choices before any floors are applied
        priority_llm = blueprint.priority
        timeout_llm  = blueprint.timeout

        priority = blueprint.priority
        timeout  = blueprint.timeout
        if blueprint.policy_type == PolicyType.PORT_BLOCK_SPOOF:
            priority = max(priority, 65000); timeout = max(timeout, 1800)
        elif blueprint.policy_type == PolicyType.COMPLETE_IP_BLOCK:
            priority = max(priority, 45000); timeout = max(timeout, 1800)
        elif blueprint.policy_type == PolicyType.DNP3_PORT_BLOCK:
            priority = max(priority, 40000); timeout = max(timeout, 600)

        overrode_priority = (priority != priority_llm)
        overrode_timeout  = (timeout  != timeout_llm)
        override_count    = int(overrode_priority) + int(overrode_timeout)
        if overrode_priority:
            logger.warning(
                f"Serializer override: priority {priority_llm}→{priority} "
                f"(policy={blueprint.policy_type.value})"
            )
        if overrode_timeout:
            logger.warning(
                f"Serializer override: timeout {timeout_llm}→{timeout}s "
                f"(policy={blueprint.policy_type.value})"
            )

        # Build selector — exact same structure as the real ONOS examples above
        if blueprint.selector_type == SelectorType.IN_PORT:
            # PORT_BLOCK_SPOOF: IN_PORT only, no ETH_TYPE / IP_PROTO needed
            criteria = [{"type": "IN_PORT", "port": str(blueprint.selector_value)}]
        else:
            # IPV4_SRC: ensure /32 notation
            ip_val = blueprint.selector_value
            if "/" not in ip_val:
                ip_val = f"{ip_val}/32"
            criteria = [
                {"type": "ETH_TYPE", "ethType": "0x800"},
                {"type": "IP_PROTO",  "protocol": 6},
                {"type": "IPV4_SRC",  "ip": ip_val},
            ]
            # DNP3_PORT_BLOCK adds TCP_DST 20000
            if blueprint.policy_type == PolicyType.DNP3_PORT_BLOCK:
                criteria.append({"type": "TCP_DST", "tcpPort": 20000})

        # Treatment differs only for ENHANCED_MONITORING
        if blueprint.policy_type == PolicyType.ENHANCED_MONITORING:
            instructions = [{"type": "OUTPUT", "port": "CONTROLLER"}]
        else:
            instructions = [{"type": "NOACTION"}]

        flow_rule = {
            "priority":    priority,
            "isPermanent": False,
            "timeout":     timeout,
            "deviceId":    blueprint.target_device,
            "treatment":   {"instructions": instructions, "deferred": []},
            "selector":    {"criteria": criteria},
        }

        return {
            "policy_metadata": {
                "alert_id":          intel["alert_id"],
                "generated_at":      datetime.now(timezone.utc).isoformat(),
                "threat_level":      blueprint.threat_level.value,
                "policy_type":       blueprint.policy_type.value,
                "llm_model_used":    intel.get("_llm_model", self.llm_model),
                "explanation":       blueprint.explanation_summary,
                "llm_reason":        blueprint.reason,
                "priority_applied":  priority,
                "timeout_applied":   timeout,
            },
            "flow_rules": [flow_rule],
            "deployment_strategy": {
                "target_switches": [blueprint.target_device],
                "priority":        priority,
                "duration":        timeout,
                "scope":           blueprint.policy_type.value,
            },
            # E11: serializer override tracking
            "serializer_overrides": {
                "overrode_priority": overrode_priority,
                "priority_llm":      priority_llm,
                "priority_applied":  priority,
                "overrode_timeout":  overrode_timeout,
                "timeout_llm":       timeout_llm,
                "timeout_applied":   timeout,
                "override_count":    override_count,
            },
        }

    def deploy_to_onos(self, policy: Dict) -> Tuple[Dict, float]:
        results = []; t = time.perf_counter()
        for rule in policy.get("flow_rules", []):
            try:
                resp = requests.post(
                    f"http://{self.onos_ip}:{self.onos_port}/onos/v1/flows",
                    json={"flows": [rule]},
                    auth=self.onos_auth,
                    params={"appId": "org.onosproject.llm"},
                    timeout=10,
                )
                if resp.status_code in {200, 201}:
                    results.append({"device": rule["deviceId"],
                                    "status": "SUCCESS", "code": resp.status_code})
                    logger.info(f"Deployed -> {rule['deviceId']} "
                                f"[{policy['deployment_strategy']['scope']}]")
                else:
                    results.append({"device": rule["deviceId"], "status": "FAILED",
                                    "code": resp.status_code, "error": resp.text})
                    logger.error(f"Deploy failed {rule['deviceId']}: {resp.text}")
            except Exception as e:
                results.append({"device": rule["deviceId"],
                                "status": "ERROR", "error": str(e)})
                logger.error(f"Deploy error: {e}")
        elapsed_ms = round((time.perf_counter() - t) * 1000, 2)
        return {
            "deployment_summary": {
                "total_rules":   len(policy["flow_rules"]),
                "successful":    sum(1 for r in results if r["status"] == "SUCCESS"),
                "failed":        sum(1 for r in results if r["status"] != "SUCCESS"),
                "deployment_time": datetime.now(timezone.utc).isoformat(),
            },
            "rule_details": results,
        }, elapsed_ms

    def process_alert(self, alert: Dict) -> Dict:
        t0       = time.perf_counter()
        alert_id = alert.get("alert_id", "?")
        logger.info(f"Pipeline: #{alert_id}  [{alert.get('type')} / "
                    f"{alert.get('attack_vector')}]")

        intel              = self.extract_intelligence(alert)
        rag_context, rmeta = self.rag.retrieve_context(intel)
        scaffold           = self._build_deterministic_scaffold(intel)

        # ── Pass 1: blueprint generation ──────────────────────────────
        prompt            = self.build_policy_prompt(intel, rag_context)
        blueprint, rp1, p1_elapsed = self.query_blueprint(prompt, intel)
        intel["_llm_model"]         = self.llm_model
        intel["_llm_response_time"] = p1_elapsed

        if blueprint is None:
            reason  = "Pass 1 blueprint generation failed"
            total_s = round(time.perf_counter() - t0, 2)
            self.explainer.write_audit_record(
                intel=intel, analysis=None, blueprint=None,
                policy={"flow_rules": [], "deployment_strategy": {}},
                deployment={"deployment_summary": {}},
                raw_prompt=prompt, raw_llm_response=rp1,
                rag_context=rag_context, retrieval_meta=rmeta,
                decision=DeploymentDecision.REJECT,
                findings=[reason], narrative=f"LLM FAILURE: {reason}",
                llm_failure=True, llm_failure_reason=reason,
                total_pipeline_time_s=total_s,
                detection_latency_ms=intel.get("_detection_latency_ms"),
                safety_mode=self.safety_mode,
            )
            return {"execution_summary": {"alert_id": alert_id,
                                          "status": "LLM_FAILURE",
                                          "reason": reason,
                                          "total_time_s": total_s}}

        # Build LLMResponse from blueprint (for narrative/audit compat)
        analysis = LLMResponse(
            threat_level=blueprint.threat_level, policy_type=blueprint.policy_type,
            confidence_score=blueprint.confidence_score,
            explanation_summary=blueprint.explanation_summary,
            target_device=blueprint.target_device, selector_type=blueprint.selector_type,
            selector_value=blueprint.selector_value, priority=blueprint.priority,
            timeout=blueprint.timeout, reason=blueprint.reason,
            step1_reasoning=(f"FC-{intel['function_code']} "
                             f"({intel['function_description']}) is "
                             f"{intel['fc_severity']}-severity."),
            step2_reasoning=scaffold["step2_fact"],
            step3_reasoning=scaffold["step3_fact"],
            step4_reasoning=scaffold["step4_fact"],
            step5_reasoning=scaffold["step5_fact"],
        )

        # B3: serialize to ONOS — thin, no decisions
        policy = self.serialize_blueprint_to_onos(intel, blueprint)
        serializer_overrides = policy.get("serializer_overrides", {})

        # ── Safety gate (ablation-aware) ───────────────────────────────
        decision: DeploymentDecision = DeploymentDecision.REJECT
        findings: List[str]          = []
        block_reasons: Dict          = dict(SafetyValidator._EMPTY_REASONS)
        would_have_been_blocked      = False
        would_have_findings: List[str] = []
        would_have_block_reasons: Dict = {}   # populated only in safety_mode=disabled

        if self.safety_mode == "disabled":
            logger.warning(f"[SAFETY DISABLED] #{alert_id} — shadow only")
            would_have_block_reasons: Dict = dict(SafetyValidator._EMPTY_REASONS)
            try:
                sd, sf, sr = self.validator.validate(intel, blueprint, rmeta)
                would_have_block_reasons = sr
                if sd in (DeploymentDecision.REJECT, DeploymentDecision.HUMAN_REVIEW):
                    would_have_been_blocked = True
                    would_have_findings = sf
                    logger.warning(f"[SAFETY DISABLED] would have been {sd.value}: {sf}")
                else:
                    would_have_findings = sf
            except SafetyViolation as sv:
                would_have_block_reasons = sv.reasons   # full breakdown preserved
                would_have_been_blocked = True
                would_have_findings = [f"WOULD_HAVE_BLOCKED: {sv}"]
                logger.warning(f"[SAFETY DISABLED] SafetyViolation would have fired: {sv}")
            decision = DeploymentDecision.AUTO_DEPLOY
            findings = ["[SAFETY VALIDATOR BYPASSED — ablation mode]"] + would_have_findings
        else:
            try:
                decision, findings, block_reasons = self.validator.validate(intel, blueprint, rmeta)
            except SafetyViolation as sv:
                findings      = [str(sv)]
                decision      = DeploymentDecision.REJECT
                block_reasons = sv.reasons   # full per-category breakdown preserved
                logger.critical(f"SafetyViolation #{alert_id}: {sv}")

        # ── Deployment ─────────────────────────────────────────────────
        deployment: Dict         = {"deployment_summary": {}}
        onos_ms: Optional[float] = None
        if decision == DeploymentDecision.AUTO_DEPLOY:
            deployment, onos_ms = self.deploy_to_onos(policy)
            logger.info(f"AUTO_DEPLOY #{alert_id}  ONOS={onos_ms}ms")
        elif decision == DeploymentDecision.HUMAN_REVIEW:
            logger.warning(f"HUMAN_REVIEW #{alert_id}  conf={blueprint.confidence_score}")
        else:
            logger.error(f"REJECT #{alert_id}  findings={findings}")

        # B5: blueprint accuracy
        accuracy = self._compute_blueprint_accuracy(intel, blueprint)
        total_s  = round(time.perf_counter() - t0, 2)
        narrative = self.explainer.build_operator_narrative(
            intel, analysis, decision, findings
        )

        self.explainer.write_audit_record(
            intel=intel, analysis=analysis, blueprint=blueprint,
            policy=policy, deployment=deployment,
            raw_prompt=prompt, raw_llm_response=rp1,
            rag_context=rag_context, retrieval_meta=rmeta,
            decision=decision, findings=findings, narrative=narrative,
            total_pipeline_time_s=total_s,
            detection_latency_ms=intel.get("_detection_latency_ms"),
            onos_deployment_ms=onos_ms, explainability_source="SCAFFOLD",
            safety_mode=self.safety_mode,
            would_have_been_blocked=would_have_been_blocked,
            would_have_findings=would_have_findings,
            would_have_block_reasons=would_have_block_reasons,
            block_reasons=block_reasons,
            serializer_overrides=serializer_overrides,
            **accuracy,
        )

        if decision == DeploymentDecision.AUTO_DEPLOY:
            nid = self.rag.ingest_confirmed_attack(intel, blueprint.policy_type.value)
            if nid: logger.info(f"RAG updated: {nid} (#{alert_id})")

        status = (
            "SUCCESS"      if decision == DeploymentDecision.AUTO_DEPLOY  else
            "HUMAN_REVIEW" if decision == DeploymentDecision.HUMAN_REVIEW else
            "REJECTED"
        )

        print("\n" + "-" * 90)
        print(
            f"  ALERT #{alert_id}  |  {intel['attack_vector']}  |  "
            f"{blueprint.policy_type.value}  |  {decision.value}  |  "
            f"bp_correct={accuracy['blueprint_correct']}  |  "
            f"safety={self.safety_mode}  |  would_block={would_have_been_blocked}"
        )
        print("-" * 90); print(narrative); print("-" * 90 + "\n")

        result = {
            "execution_summary": {
                "alert_id":              alert_id,
                "attack_vector":         intel["attack_vector"],
                "status":                status,
                "deployment_decision":   decision.value,
                "pass1_time_s":          p1_elapsed,
                "total_time_s":          total_s,
                "llm_model":             self.llm_model,
                "policy_type_chosen":    blueprint.policy_type.value,
                "target_device_chosen":  blueprint.target_device,
                "selector_type_chosen":  blueprint.selector_type.value,
                "blueprint_correct":     accuracy["blueprint_correct"],
                "safety_mode":           self.safety_mode,
                "would_have_been_blocked": would_have_been_blocked,
                # E11: block reason summary
                "blocked_due_to_structure":         block_reasons.get("blocked_due_to_structure",         False),
                "blocked_due_to_confidence":        block_reasons.get("blocked_due_to_confidence",        False),
                "blocked_due_to_wrong_selector":    block_reasons.get("blocked_due_to_wrong_selector",    False),
                "blocked_due_to_wrong_target":      block_reasons.get("blocked_due_to_wrong_target",      False),
                "blocked_due_to_severity_mismatch": block_reasons.get("blocked_due_to_severity_mismatch", False),
                "severity_policy_mismatch":         block_reasons.get("severity_policy_mismatch",         False),
                # E11: serializer overrides
                "serializer_overrode_priority": serializer_overrides.get("overrode_priority", False),
                "serializer_overrode_timeout":  serializer_overrides.get("overrode_timeout",  False),
                "serializer_override_count":    serializer_overrides.get("override_count",    0),
                "explainability_status": "PENDING",
            },
            "blueprint":          blueprint.model_dump(),
            "safety_findings":    findings,
            "block_reasons":      block_reasons,
            "blueprint_accuracy": accuracy,
            "serializer_overrides": serializer_overrides,
            "deployment_result":  deployment,
            "operator_narrative": narrative,
        }

        # ── Pass 2: async explainability ───────────────────────────────
        def _pass2():
            tid = threading.get_ident(); self.explainer._register(tid)
            try:
                ep = self.build_explainability_prompt(intel, rag_context, blueprint, scaffold)
                er, rp2, p2e = self.query_explainability(ep)
                if er is not None:
                    analysis.step1_reasoning = er.step1_protocol
                    analysis.step2_reasoning = er.step2_source_validation
                    analysis.step3_reasoning = er.step3_victim_response
                    analysis.step4_reasoning = er.step4_topology
                    analysis.step5_reasoning = er.step5_safety_check
                    enriched = self.explainer.build_operator_narrative(
                        intel, analysis, decision, findings
                    )
                    self.explainer.write_audit_record(
                        intel=intel, analysis=analysis, blueprint=blueprint,
                        policy=policy, deployment=deployment,
                        raw_prompt=ep, raw_llm_response=rp2,
                        rag_context=rag_context, retrieval_meta=rmeta,
                        decision=decision, findings=findings, narrative=enriched,
                        pass2_time_s=p2e, total_pipeline_time_s=total_s,
                        detection_latency_ms=intel.get("_detection_latency_ms"),
                        onos_deployment_ms=onos_ms,
                        explainability_source="LLM_PASS2",
                        record_stage="enriched",
                        safety_mode=self.safety_mode,
                        would_have_been_blocked=would_have_been_blocked,
                        would_have_findings=would_have_findings,
                        would_have_block_reasons=would_have_block_reasons,
                        block_reasons=block_reasons,
                        serializer_overrides=serializer_overrides,
                        **accuracy,
                    )
                    result["execution_summary"]["explainability_status"] = "SUCCESS"
                    result["execution_summary"]["pass2_time_s"] = p2e
                    logger.info(f"[Pass 2] Enriched #{alert_id} in {p2e}s")
                else:
                    result["execution_summary"]["explainability_status"] = "SCAFFOLD_ONLY"
            finally:
                self.explainer._deregister(tid)

        threading.Thread(target=_pass2, daemon=True).start()
        return result


# ============================================================
# DETECTOR  (unchanged from E10)
# ============================================================

class GridCADDetector:
    def __init__(self):
        self.running = False
        self.master_ip       = MASTER_IP
        self.master_location = MASTER_LOCATION
        self.onos_ip    = "172.20.0.5"; self.onos_port = "8181"
        self.onos_auth  = ("onos", "rocks")
        self.grouping_window      = 0.5
        self.dedup_window         = 1
        self.ingress_collect_window = 0.40
        self.spoof_dedup_window   = 5
        self.block_expiry         = 1800
        self.alert_counter        = 1
        self.attack_events:   Dict = {}
        self.attack_sessions: Dict = {}
        self.recent_alerts:   Dict = {}
        self.ingress_collector: Dict = {}
        self.spoof_dedup:     Dict = {}
        self.blocked_ports:   Dict = {}
        self.llm_engine: Optional[LLMPolicyEngine] = None
        self.enable_llm  = False; self.llm_model   = "phi4-mini"
        self.rag_persist = "./chroma_db"; self.audit_log = "./audit_log.jsonl"
        self.rag_mode    = "full"; self.safety_mode = "enabled"
        logger.info("GridCAD Detector initialised")

    @staticmethod
    def classify_fc_severity(fc: int) -> str:
        if fc in {13, 18}: return "CRITICAL"
        if fc in {14, 21}: return "HIGH"
        return "LOW"

    @staticmethod
    def extract_function_code(payload_hex: str) -> Optional[int]:
        if not payload_hex or len(payload_hex) < 20: return None
        try:
            if not payload_hex.startswith("0564"): return None
            for pos in [24, 22, 26, 20, 28]:
                if len(payload_hex) > pos + 1:
                    try:
                        fc = int(payload_hex[pos:pos + 2], 16)
                        if fc in ADMIN_FCS or fc in {0, 1, 129, 130}: return fc
                    except (ValueError, IndexError): continue
            for i in range(4, len(payload_hex) - 2, 2):
                try:
                    fc = int(payload_hex[i:i + 2], 16)
                    if fc in ADMIN_FCS: return fc
                except (ValueError, IndexError): continue
        except Exception: pass
        return None

    @staticmethod
    def interface_to_location(iface: str) -> Optional[Tuple[str, str]]:
        m = re.match(r"^(s\d+)-eth(\d+)$", iface.strip())
        if not m: return None
        d = SWITCH_TO_DEVICE.get(m.group(1))
        return (d, m.group(2)) if d else None

    def handle_master_claimed_packet(self, ts, src_ip, dst_ip, dst_port, fc, iface):
        t_in = time.perf_counter()
        actual = self.interface_to_location(iface)
        t_topo = time.perf_counter()
        if actual is None or actual == self.master_location: return
        now = time.perf_counter(); dk = (src_ip, dst_ip, fc)
        if (now - self.spoof_dedup.get(dk, 0)) < self.spoof_dedup_window: return
        col = self.ingress_collector.get(dk)
        if col is None:
            col = {"first_seen": now, "locations": set(), "alerted": False,
                   "t1": t_in, "t2": t_topo, "timestamp": ts, "dst_port": dst_port}
            self.ingress_collector[dk] = col; self.spoof_dedup[dk] = now
            threading.Timer(self.ingress_collect_window,
                            self._fire_spoof_alert, args=[dk, src_ip, dst_ip, fc]).start()
        col["locations"].add(actual)
        now2 = time.perf_counter()
        self.ingress_collector = {k: v for k, v in self.ingress_collector.items()
                                  if (now2 - v["first_seen"]) < self.ingress_collect_window * 4}

    def _find_host_facing_port(self, locations):
        if len(locations) == 1: return next(iter(locations))
        try:
            r = requests.get(f"http://{self.onos_ip}:{self.onos_port}/onos/v1/links",
                             auth=self.onos_auth, timeout=3)
            r.raise_for_status()
            infra = set()
            for link in r.json().get("links", []):
                for ep in ("src", "dst"):
                    d = link.get(ep, {})
                    if d.get("device") and d.get("port"):
                        infra.add((d["device"], str(d["port"])))
            hf = [loc for loc in locations if loc not in infra]
            if hf: return hf[0]
        except Exception as e: logger.warning(f"ONOS links failed: {e}")
        return next(iter(locations))

    def _fire_spoof_alert(self, dk, src_ip, dst_ip, fc):
        col = self.ingress_collector.pop(dk, None)
        if col is None or col["alerted"]: return
        col["alerted"] = True
        ingress = self._find_host_facing_port(col["locations"])
        if ingress is None: return
        det_ms  = round((col["t2"] - col["t1"]) * 1000, 2)
        fc_desc = FC_META.get(fc, (f"FC-{fc}",))[0]
        fc_sev  = self.classify_fc_severity(fc)
        logger.critical(f"[TOPOLOGY VIOLATION] Spoofed master: {src_ip} at {ingress} FC-{fc}")
        alert = {
            "alert_id": f"{self.alert_counter:03d}",
            "type":     "MASTER_IMPERSONATION_ATTACK",
            "attack_vector": "IP_SPOOFED",
            "time":     datetime.now(timezone.utc).isoformat(),
            "attack_summary": {
                "attacker_ip": src_ip, "attacker_station": None,
                "victim_ip": dst_ip,   "victim_station": int(dst_ip.split(".")[-1]),
                "success_indicators": False,
            },
            "attack_command": {
                "function_code": fc, "function_description": fc_desc,
                "fc_severity": fc_sev, "timestamp": col["timestamp"],
                "target_port": col["dst_port"],
            },
            "topology_violation": {
                "expected_location": list(self.master_location),
                "actual_location":   list(ingress),
                "ingress_location":  list(ingress),
                "all_observed_ports": [list(l) for l in col["locations"]],
            },
            "victim_responses": [],
            "confidence": 1.0,
            "explanation": f"IP-spoofed Master Impersonation FC-{fc}. Ingress: {ingress}.",
            "latency_log": {"t1": col["t1"], "t2": col["t2"], "detection_ms": det_ms},
        }
        self._output_alert(alert)
        self.spoof_dedup[dk] = time.perf_counter()
        port_key  = tuple(ingress); now_wall = time.time()
        expiry    = getattr(self, "block_expiry_override", self.block_expiry)
        if (now_wall - self.blocked_ports.get(port_key, 0)) < expiry:
            logger.warning(f"Port {port_key} already blocked")
        else:
            self.blocked_ports[port_key] = now_wall; self._dispatch_llm(alert)
        self.alert_counter += 1

    def add_attack_event(self, ts, src_ip, dst_ip, dst_port, fc, event_type):
        if fc in ADMIN_FCS:   key, is_cmd = (src_ip, dst_ip), True
        elif fc == 130 and dst_ip != self.master_ip: key, is_cmd = (dst_ip, src_ip), False
        else: return
        now = datetime.now()
        if key not in self.attack_events:
            self.attack_events[key] = {
                "attacker_ip": key[0], "victim_ip": key[1],
                "created_time": now, "attack_command": None,
                "victim_responses": [], "t1_packet_in": time.perf_counter(),
            }
        ev = self.attack_events[key]
        if is_cmd:
            ev["attack_command"] = {
                "timestamp": ts, "function_code": fc,
                "fc_severity": self.classify_fc_severity(fc),
                "dst_port": dst_port, "event_type": event_type,
                "t_cmd_received": time.perf_counter(),
            }
        else:
            ev["victim_responses"].append({"timestamp": ts,
                                           "function_code": fc, "dst_port": dst_port})
        self._track_session(key[0], key[1], fc)
        threading.Timer(self.grouping_window, self._finalize_event, args=[key]).start()

    def _finalize_event(self, key):
        ev = self.attack_events.pop(key, None)
        if not ev or not ev["attack_command"]: return
        if not self._should_alert(key[0], key[1]): return
        self._generate_injection_alert(ev)

    def _generate_injection_alert(self, ev):
        fc      = ev["attack_command"]["function_code"]
        fc_desc = FC_META.get(fc, (f"FC-{fc}",))[0]
        fc_sev  = ev["attack_command"].get("fc_severity", self.classify_fc_severity(fc))
        responses = ev["victim_responses"]
        attacker  = ev["attacker_ip"]; victim = ev["victim_ip"]
        conf   = self._calculate_confidence(ev); t2 = time.perf_counter()
        t_cmd  = ev.get("attack_command", {}).get("t_cmd_received", ev.get("t1_packet_in", t2))
        det_ms = round((t2 - t_cmd) * 1000, 2)
        alert = {
            "alert_id": f"{self.alert_counter:03d}",
            "type":     "FC_INJECTION_ATTACK", "attack_vector": "FC_INJECTION",
            "time":     datetime.now(timezone.utc).isoformat(),
            "attack_summary": {
                "attacker_ip": attacker, "attacker_station": int(attacker.split(".")[-1]),
                "victim_ip": victim,     "victim_station":   int(victim.split(".")[-1]),
                "success_indicators": len(responses) > 0,
            },
            "attack_command": {
                "function_code": fc, "function_description": fc_desc,
                "fc_severity": fc_sev, "timestamp": ev["attack_command"]["timestamp"],
                "target_port": ev["attack_command"]["dst_port"],
            },
            "victim_responses": [
                {"function_code": r["function_code"], "timestamp": r["timestamp"],
                 "source_port": r["dst_port"]}
                for r in responses
            ],
            "confidence": round(conf, 2),
            "explanation": (
                f"Outstation {attacker.split('.')[-1]} issued {fc_desc} "
                f"(FC-{fc}) to outstation {victim.split('.')[-1]}. " +
                (f"Victim confirmed with {len(responses)} FC-130." if responses else "No FC-130.")
            ),
            "latency_log": {
                "t1_packet_in": ev.get("t1_packet_in"), "t2_detection": t2,
                "detection_ms": det_ms,
                "grouping_window_ms": round(self.grouping_window * 1000),
            },
        }
        self._output_alert(alert); self._dispatch_llm(alert); self.alert_counter += 1

    def _dispatch_llm(self, alert):
        if not self.enable_llm or self.llm_engine is None:
            logger.info(f"LLM disabled — #{alert.get('alert_id')} logged only"); return
        def _run():
            try:
                t0 = time.perf_counter()
                result = self.llm_engine.process_alert(alert)
                elapsed = round(time.perf_counter() - t0, 2)
                status  = result.get("execution_summary", {}).get("status", "?")
                logger.info(f"LLM done: #{alert.get('alert_id')} {status} {elapsed}s")
            except Exception as e:
                logger.error(f"LLM error #{alert.get('alert_id')}: {e}")
        threading.Thread(target=_run, daemon=True).start()

    def process_raw_packet(self, line):
        try:
            f = line.strip().split("\t")
            if len(f) < 7: return
            ts, src_ip, dst_ip = f[0], f[1], f[2]
            dst_port = int(f[4]) if f[4] else 0
            iface    = f[5]; payload = f[6]
            if not payload: return
            fc = self.extract_function_code(payload)
            if fc is None or fc not in ADMIN_FCS: return
            if src_ip == self.master_ip:
                self.handle_master_claimed_packet(ts, src_ip, dst_ip, dst_port, fc, iface)
            else:
                self.add_attack_event(ts, src_ip, dst_ip, dst_port, fc, "ADMIN_COMMAND")
        except Exception as e: logger.debug(f"Raw packet error: {e}")

    def process_dissected_packet(self, line):
        try:
            f = line.strip().split("\t")
            if len(f) < 6: return
            ts = f[0]; src_ip, dst_ip = f[1], f[2]
            dst_port = int(f[4]) if f[4] else 0
            fc       = int(f[5]) if f[5] else 0
            if fc == 130 and dst_ip != self.master_ip:
                self.add_attack_event(ts, src_ip, dst_ip, dst_port, fc, "VICTIM_RESPONSE")
        except Exception as e: logger.debug(f"Dissected error: {e}")

    def _should_alert(self, attacker, victim) -> bool:
        now = datetime.now(); key = (attacker, victim)
        if key in self.recent_alerts:
            if (now - self.recent_alerts[key]).total_seconds() < self.dedup_window:
                return False
        self.recent_alerts[key] = now
        cutoff = now - timedelta(seconds=self.dedup_window * 2)
        self.recent_alerts = {k: v for k, v in self.recent_alerts.items() if v > cutoff}
        return True

    def _track_session(self, src, dst, fc):
        key = f"{src}->{dst}"; now = datetime.now()
        if key not in self.attack_sessions:
            self.attack_sessions[key] = {"first_seen": now, "last_seen": now,
                                         "attack_count": 0, "response_count": 0, "fcs": set()}
        s = self.attack_sessions[key]; s["last_seen"] = now; s["fcs"].add(fc)
        if fc in ADMIN_FCS: s["attack_count"]  += 1
        elif fc == 130:     s["response_count"] += 1

    def _calculate_confidence(self, ev) -> float:
        conf = 0.0; a, v = ev["attacker_ip"], ev["victim_ip"]
        if (a != self.master_ip and v != self.master_ip
                and a.startswith("10.0.0.") and v.startswith("10.0.0.")):
            conf += 0.6
        fc = ev["attack_command"]["function_code"]
        if fc in ADMIN_FCS: conf += 0.3
        responses = ev["victim_responses"]
        if responses:       conf += 0.15
        if len(responses) > 1: conf += 0.05
        if fc in {13, 18}:  conf += 0.05
        return min(conf, 1.0)

    def _output_alert(self, alert):
        sev = alert["attack_command"].get("fc_severity", "?")
        print("\n" + "=" * 100)
        print(f"  GRIDCAD ALERT #{alert['alert_id']}  |  {alert['type']}  |  "
              f"VECTOR: {alert.get('attack_vector')}  |  "
              f"FC-{alert['attack_command']['function_code']}  "
              f"SEV={sev}  conf={alert.get('confidence')}")
        print("=" * 100); print(json.dumps(alert, indent=2)); print("=" * 100 + "\n")

    def cleanup(self):
        now = datetime.now()
        for k in [k for k, v in self.attack_events.items()
                  if (now - v["created_time"]).total_seconds() > self.grouping_window * 2]:
            del self.attack_events[k]
        cutoff = now - timedelta(minutes=5)
        for k in [k for k, v in self.attack_sessions.items()
                  if v["last_seen"] < cutoff]:
            del self.attack_sessions[k]

    @staticmethod
    def get_switch_interfaces():
        try:
            r = subprocess.run(["ip", "link", "show"], capture_output=True,
                               text=True, timeout=5)
            ifaces = sorted(set(re.findall(r"(s\d+-eth\d+)", r.stdout)))
            if ifaces: logger.info(f"Discovered {len(ifaces)} switch interfaces"); return ifaces
        except Exception as e: logger.warning(f"Interface discovery failed: {e}")
        return ["any"]

    def start_monitoring(self):
        self.running = True
        if self.enable_llm:
            try:
                self.llm_engine = LLMPolicyEngine(
                    onos_ip=self.onos_ip, llm_model=self.llm_model,
                    rag_persist=self.rag_persist, audit_log=self.audit_log,
                    rag_mode=self.rag_mode, safety_mode=self.safety_mode,
                )
            except Exception as e:
                logger.error(f"LLM engine init failed: {e} — disabled")
                self.enable_llm = False

        switch_ifaces = self.get_switch_interfaces()
        iface_args    = [arg for i in switch_ifaces for arg in ("-i", i)]
        raw_cmd = [
            "tshark", "-l", "-n", *iface_args,
            "-f", "tcp portrange 20002-20024", "-Y", "tcp and frame.len > 60",
            "-T", "fields",
            "-e", "frame.time_epoch", "-e", "ip.src",  "-e", "ip.dst",
            "-e", "tcp.srcport",      "-e", "tcp.dstport",
            "-e", "frame.interface_name", "-e", "tcp.payload",
        ]
        dnp3_decode = [arg for p in range(20002, 20025) for arg in ("-d", f"tcp.port=={p},dnp3")]
        dnp3_cmd = [
            "tshark", "-l", "-n", "-i", "any",
            "-f", "tcp portrange 20002-20024", *dnp3_decode,
            "-Y", "dnp3", "-T", "fields",
            "-e", "frame.time_epoch", "-e", "ip.src",    "-e", "ip.dst",
            "-e", "tcp.srcport",      "-e", "tcp.dstport", "-e", "dnp3.al.func",
        ]
        logger.info(f"GridCAD monitoring  master={self.master_ip}  "
                    f"LLM={'ON' if self.enable_llm else 'OFF'}  "
                    f"safety={self.safety_mode}")

        def mon_raw():
            p = subprocess.Popen(raw_cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True, bufsize=1)
            for line in iter(p.stdout.readline, ""):
                if not self.running: break
                if line.strip(): self.process_raw_packet(line)
            p.terminate()

        def mon_dnp3():
            p = subprocess.Popen(dnp3_cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True, bufsize=1)
            for line in iter(p.stdout.readline, ""):
                if not self.running: break
                if line.strip(): self.process_dissected_packet(line)
            p.terminate()

        threading.Thread(target=mon_raw,  daemon=True).start()
        threading.Thread(target=mon_dnp3, daemon=True).start()
        cycle = 0
        while self.running:
            time.sleep(15); cycle += 1; self.cleanup()
            logger.info(f"Cycle {cycle}  alerts={self.alert_counter - 1}  "
                        f"sessions={len(self.attack_sessions)}")

    def stop(self):
        logger.info("GridCAD stopping..."); self.running = False
        if self.enable_llm and self.llm_engine:
            pending = self.llm_engine.explainer.pending_pass2_count()
            if pending > 0:
                logger.info(f"Waiting for {pending} Pass 2 thread(s)...")
                self.llm_engine.wait_for_pass2(timeout=90.0)


# ============================================================
# CLI
# ============================================================

def main():
    ap = argparse.ArgumentParser(description="GridCAD Unified — blueprint edition")
    ap.add_argument("--enable-llm",      action="store_true")
    ap.add_argument("--onos-ip",         default="172.20.0.5")
    ap.add_argument("--master-ip",       default="10.0.0.1")
    ap.add_argument("--master-device",   default="of:0000000000000001")
    ap.add_argument("--master-port",     default="1")
    ap.add_argument("--llm-model",       default="phi4-mini")
    ap.add_argument("--rag-persist",     default="./chroma_db")
    ap.add_argument("--audit-log",       default="./audit_log.jsonl")
    ap.add_argument("--grouping-window", type=float, default=0.5)
    ap.add_argument("--dedup-window",    type=int,   default=1)
    ap.add_argument("--rag-mode",    choices=["disabled", "seed_only", "full"], default="full")
    ap.add_argument("--safety-mode", choices=["enabled", "disabled"],           default="enabled",
                    help="'enabled'=normal gate. 'disabled'=bypass+log what would block.")
    ap.add_argument("--experiment-mode", action="store_true",
                    help="Sets block_expiry to 15s for rapid re-attack testing.")
    ap.add_argument("--test-alert", action="store_true")
    ap.add_argument("--test-spoof", action="store_true")
    ap.add_argument("--debug",      action="store_true")
    args = ap.parse_args()

    if args.debug: logging.getLogger().setLevel(logging.DEBUG)

    if args.test_alert or args.test_spoof:
        engine = LLMPolicyEngine(
            onos_ip=args.onos_ip, llm_model=args.llm_model,
            rag_persist=args.rag_persist, audit_log=args.audit_log,
            rag_mode=args.rag_mode, safety_mode=args.safety_mode,
        )
        now_iso = datetime.now(timezone.utc).isoformat()
        if args.test_spoof:
            alert = {
                "alert_id": "TEST-SPOOF-001",
                "type": "MASTER_IMPERSONATION_ATTACK", "attack_vector": "IP_SPOOFED",
                "time": now_iso,
                "attack_summary": {"attacker_ip": "10.0.0.1", "attacker_station": None,
                                   "victim_ip": "10.0.0.15", "victim_station": 15,
                                   "success_indicators": False},
                "attack_command": {"function_code": 13, "function_description": "Cold Restart",
                                   "fc_severity": "CRITICAL", "timestamp": now_iso,
                                   "target_port": 20015},
                "topology_violation": {
                    "expected_location": ["of:0000000000000001", "1"],
                    "actual_location":   ["of:0000000000000002", "3"],
                    "ingress_location":  ["of:0000000000000002", "3"],
                    "all_observed_ports": [["of:0000000000000002", "3"]],
                },
                "victim_responses": [], "confidence": 1.0,
                "explanation": "Test: spoofed master FC-13.",
                "latency_log": {"detection_ms": 12.5},
            }
        else:
            alert = {
                "alert_id": "TEST-INJ-001",
                "type": "FC_INJECTION_ATTACK", "attack_vector": "FC_INJECTION",
                "time": now_iso,
                "attack_summary": {"attacker_ip": "10.0.0.6", "attacker_station": 6,
                                   "victim_ip": "10.0.0.24", "victim_station": 24,
                                   "success_indicators": True},
                "attack_command": {"function_code": 13, "function_description": "Cold Restart",
                                   "fc_severity": "CRITICAL", "timestamp": now_iso,
                                   "target_port": 20024},
                "victim_responses": [{"function_code": 130, "timestamp": now_iso,
                                      "source_port": 33028}],
                "confidence": 0.95,
                "explanation": "Test: outstation 6 Cold Restart to outstation 24.",
                "latency_log": {"detection_ms": 8.3},
            }
        result = engine.process_alert(alert)
        print("\n" + "=" * 80 + "\nTEST RESULT\n" + "=" * 80)
        print(json.dumps(result, indent=2, default=str))
        return

    detector = GridCADDetector()
    detector.enable_llm      = args.enable_llm
    detector.onos_ip         = args.onos_ip
    detector.master_ip       = args.master_ip
    detector.master_location = (args.master_device, args.master_port)
    detector.llm_model       = args.llm_model
    detector.rag_persist     = args.rag_persist
    detector.audit_log       = args.audit_log
    detector.grouping_window = args.grouping_window
    detector.dedup_window    = args.dedup_window
    detector.rag_mode        = args.rag_mode
    detector.safety_mode     = args.safety_mode
    if args.experiment_mode:
        detector.block_expiry_override = 15
        logger.info("Experiment mode: block_expiry=15s")
    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        logger.info("Shutdown — flushing Pass 2 threads...")
    finally:
        detector.stop()


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
DNP3 Attack Detector with Rule-Based Mitigation
Detects lateral movement attacks on DNP3 traffic, generates ONOS flow rules,
and deploys them to block the attacker.

Topology: 12 switches, 24 hosts (h1=master, h2-h24=outstations)
          2 hosts per switch, 4 switches per ONOS controller group
"""

import subprocess
import json
import time
import logging
import threading
import requests
import struct
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List
from collections import defaultdict

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DNP3_DETECTOR")


# ===========================================================================
# SECTION 1: RULE-BASED POLICY ENGINE
# Handles: attack intelligence extraction, threat scoring,
#          ONOS policy generation, and flow rule deployment.
# ===========================================================================

class DNP3PolicyEngine:
    """
    Rule-based threat analysis and ONOS mitigation policy engine.
    No LLM dependency - all decisions are deterministic rule-based logic.
    """

    # ------------------------------------------------------------------
    # Topology constants - 12 switches, 24 hosts (2 hosts per switch)
    # Switch numbering matches Mininet topology script assignments.
    # ------------------------------------------------------------------
    SWITCH_MAPPING = {
        "s1":  "of:0000000000000001",   # h1,  h2
        "s2":  "of:0000000000000002",   # h3,  h4
        "s3":  "of:0000000000000003",   # h5,  h6
        "s4":  "of:0000000000000004",   # h7,  h8
        "s5":  "of:0000000000000005",   # h9,  h10
        "s6":  "of:0000000000000006",   # h11, h12
        "s7":  "of:0000000000000007",   # h13, h14
        "s8":  "of:0000000000000008",   # h15, h16
        "s9":  "of:0000000000000009",   # h17, h18
        "s10": "of:000000000000000a",   # h19, h20
        "s11": "of:000000000000000b",   # h21, h22
        "s12": "of:000000000000000c",   # h23, h24
    }

    HOST_SWITCH_MAP = {
        # Controller group 1: s1-s4
        "10.0.0.1": "s1",  "10.0.0.2":  "s1",
        "10.0.0.3": "s2",  "10.0.0.4":  "s2",
        "10.0.0.5": "s3",  "10.0.0.6":  "s3",
        "10.0.0.7": "s4",  "10.0.0.8":  "s4",
        # Controller group 2: s5-s8
        "10.0.0.9":  "s5", "10.0.0.10": "s5",
        "10.0.0.11": "s6", "10.0.0.12": "s6",
        "10.0.0.13": "s7", "10.0.0.14": "s7",
        "10.0.0.15": "s8", "10.0.0.16": "s8",
        # Controller group 3: s9-s12
        "10.0.0.17": "s9",  "10.0.0.18": "s9",
        "10.0.0.19": "s10", "10.0.0.20": "s10",
        "10.0.0.21": "s11", "10.0.0.22": "s11",
        "10.0.0.23": "s12", "10.0.0.24": "s12",
    }

    FC_SEVERITY = {
        13: "CRITICAL",   # Cold Restart
        18: "CRITICAL",   # Stop Application
        14: "HIGH",       # Warm Restart
        21: "HIGH",       # Disable Unsolicited
        130: "MEDIUM",    # Unsolicited Response
    }

    FC_DESCRIPTIONS = {
        13:  "Cold Restart",
        14:  "Warm Restart",
        18:  "Stop Application",
        21:  "Disable Unsolicited",
        130: "Unsolicited Response",
    }

    def __init__(self, onos_ip: str = "127.0.0.1", onos_port: str = "8181"):
        self.onos_ip   = onos_ip
        self.onos_port = onos_port
        self.onos_auth = ("onos", "rocks")
        self.onos_base = f"http://{onos_ip}:{onos_port}/onos/v1"
        logger.info("Policy engine initialized - ONOS at %s:%s", onos_ip, onos_port)

    # ------------------------------------------------------------------
    # Intelligence extraction
    # ------------------------------------------------------------------
    def extract_attack_intelligence(self, alert: Dict) -> Dict:
        """Flatten alert JSON into a flat intelligence dict for analysis."""
        summary  = alert.get("attack_summary", {})
        command  = alert.get("attack_command", {})
        responses = alert.get("victim_responses", [])

        attacker_ip = summary.get("attacker_ip")
        victim_ip   = summary.get("victim_ip")

        attacker_switch = self.HOST_SWITCH_MAP.get(attacker_ip)
        victim_switch   = self.HOST_SWITCH_MAP.get(victim_ip)

        return {
            "alert_id":             alert.get("alert_id"),
            "attack_type":          alert.get("type"),
            "timestamp":            alert.get("time"),
            "confidence":           alert.get("confidence", 0.0),
            "attacker_ip":          attacker_ip,
            "attacker_station":     summary.get("attacker_station"),
            "victim_ip":            victim_ip,
            "victim_station":       summary.get("victim_station"),
            "success_indicators":   summary.get("success_indicators", False),
            "function_code":        command.get("function_code"),
            "function_description": command.get("function_description"),
            "target_port":          command.get("target_port"),
            "victim_response_count": len(responses),
            "attacker_switch":      attacker_switch,
            "victim_switch":        victim_switch,
            "cross_switch_attack":  attacker_switch != victim_switch,
            "severity":             self.FC_SEVERITY.get(command.get("function_code"), "UNKNOWN"),
            "explanation":          alert.get("explanation", ""),
        }

    # ------------------------------------------------------------------
    # Rule-based threat scoring
    # ------------------------------------------------------------------
    def rule_based_analysis(self, intel: Dict) -> Dict:
        """
        Score threat based on function code, success indicators, confidence,
        and lateral movement. Returns threat_level and policy_recommendation.
        """
        steps = []
        score = 0.0

        # 1. Function code severity
        fc = intel.get("function_code")
        if fc in (13, 18):
            steps.append(f"FC {fc} ({intel['function_description']}) is CRITICAL - system downtime risk")
            score += 0.4
        elif fc in (14, 21):
            steps.append(f"FC {fc} ({intel['function_description']}) is HIGH - service disruption risk")
            score += 0.3
        else:
            steps.append(f"FC {fc} is low-severity")
            score += 0.1

        # 2. Attack success indicators
        resp_count = intel.get("victim_response_count", 0)
        if intel.get("success_indicators") and resp_count >= 5:
            steps.append(f"Attack confirmed successful - {resp_count} victim responses received")
            score += 0.3
        elif resp_count >= 1:
            steps.append(f"Partial success - {resp_count} victim responses received")
            score += 0.2

        # 3. Detection confidence
        conf = intel.get("confidence", 0.0)
        conf_contribution = conf * 0.2
        score += conf_contribution
        steps.append(f"Detection confidence: {conf} (contribution: {conf_contribution:.2f})")

        # 4. Lateral movement (cross-switch)
        if intel.get("cross_switch_attack"):
            steps.append(
                f"Cross-switch lateral movement: attacker on {intel['attacker_switch']}, "
                f"victim on {intel['victim_switch']}"
            )
            score += 0.1

        score = min(score, 1.0)

        # Map score to threat level and recommended action
        if score >= 0.8:
            threat_level      = "CRITICAL"
            recommendation    = "IMMEDIATE_BLOCK"
            explanation       = "Critical threat - immediate containment required"
        elif score >= 0.6:
            threat_level      = "HIGH"
            recommendation    = "SELECTIVE_BLOCK"
            explanation       = "High-impact attack - block DNP3 lateral movement traffic"
        elif score >= 0.4:
            threat_level      = "MEDIUM"
            recommendation    = "RATE_LIMIT"
            explanation       = "Suspicious activity - apply traffic limiting"
        else:
            threat_level      = "LOW"
            recommendation    = "MONITOR"
            explanation       = "Low-risk activity - enhanced monitoring only"

        return {
            "reasoning_steps":      steps,
            "threat_level":         threat_level,
            "policy_recommendation": recommendation,
            "confidence_score":     round(score, 2),
            "explanation":          explanation,
            "analysis_method":      "RULE_BASED",
        }

    # ------------------------------------------------------------------
    # ONOS policy generation
    # ------------------------------------------------------------------
    def generate_onos_policy(self, intel: Dict, analysis: Dict) -> Dict:
        """
        Build ONOS flow rule payload based on threat analysis result.
        Three modes: IMMEDIATE_BLOCK, SELECTIVE_BLOCK, MONITOR.
        """
        attacker_ip     = intel["attacker_ip"]
        attacker_switch = intel["attacker_switch"]
        device_id       = self.SWITCH_MAPPING.get(attacker_switch)

        if not device_id:
            logger.warning("No switch mapping found for attacker switch %s", attacker_switch)

        policy = {
            "policy_metadata": {
                "alert_id":          intel["alert_id"],
                "generated_at":      datetime.now(timezone.utc).isoformat(),
                "threat_level":      analysis["threat_level"],
                "policy_type":       analysis["policy_recommendation"],
                "reasoning":         analysis["explanation"],
                "analysis_method":   analysis["analysis_method"],
            },
            "flow_rules": [],
            "deployment_strategy": {
                "target_switches": [device_id] if device_id else [],
                "scope":           None,
            }
        }

        recommendation = analysis["policy_recommendation"]

        if recommendation == "IMMEDIATE_BLOCK":
            # Block all TCP traffic from attacker IP for 30 minutes
            flow_rule = {
                "priority":    45000,
                "isPermanent": False,
                "timeout":     1800,
                "deviceId":    device_id,
                "treatment":   {"instructions": []},   # empty = DROP
                "selector": {
                    "criteria": [
                        {"type": "ETH_TYPE",  "ethType": "0x0800"},
                        {"type": "IPV4_SRC",  "ip": f"{attacker_ip}/32"},
                        {"type": "IP_PROTO",  "protocol": 6},
                    ]
                }
            }
            policy["deployment_strategy"]["scope"] = "COMPLETE_IP_BLOCK"

        elif recommendation == "SELECTIVE_BLOCK":
            # Block only DNP3 port range traffic from attacker IP for 10 minutes
            flow_rule = {
                "priority":    40000,
                "isPermanent": False,
                "timeout":     600,
                "deviceId":    device_id,
                "treatment":   {"instructions": []},   # empty = DROP
                "selector": {
                    "criteria": [
                        {"type": "ETH_TYPE",  "ethType": "0x0800"},
                        {"type": "IPV4_SRC",  "ip": f"{attacker_ip}/32"},
                        {"type": "IP_PROTO",  "protocol": 6},
                        {"type": "TCP_DST",   "tcpPort": "20002-20024"},
                    ]
                }
            }
            policy["deployment_strategy"]["scope"] = "DNP3_LATERAL_MOVEMENT_BLOCK"

        else:
            # Mirror traffic to controller for enhanced monitoring, 5 minutes
            flow_rule = {
                "priority":    30000,
                "isPermanent": False,
                "timeout":     300,
                "deviceId":    device_id,
                "treatment":   {
                    "instructions": [{"type": "OUTPUT", "port": "CONTROLLER"}]
                },
                "selector": {
                    "criteria": [
                        {"type": "ETH_TYPE", "ethType": "0x0800"},
                        {"type": "IPV4_SRC", "ip": f"{attacker_ip}/32"},
                    ]
                }
            }
            policy["deployment_strategy"]["scope"] = "ENHANCED_MONITORING"

        policy["flow_rules"].append(flow_rule)
        return policy

    # ------------------------------------------------------------------
    # ONOS deployment
    # ------------------------------------------------------------------
    def deploy_policy_to_onos(self, policy: Dict) -> Dict:
        """POST flow rules to ONOS REST API. Returns deployment summary."""
        results = []

        for rule in policy["flow_rules"]:
            device_id = rule.get("deviceId")
            if not device_id:
                logger.error("Flow rule missing deviceId - skipping")
                results.append({"device": None, "status": "SKIPPED", "error": "missing deviceId"})
                continue

            try:
                url      = f"{self.onos_base}/flows"
                payload  = {"flows": [rule]}
                response = requests.post(
                    url,
                    json=payload,
                    auth=self.onos_auth,
                    params={"appId": "org.onosproject.fwd"},
                    timeout=10,
                )

                if response.status_code in (200, 201):
                    logger.info("Flow rule deployed to %s", device_id)
                    results.append({"device": device_id, "status": "SUCCESS",
                                    "response_code": response.status_code})
                else:
                    logger.error("Deploy to %s failed - HTTP %d: %s",
                                 device_id, response.status_code, response.text[:120])
                    results.append({"device": device_id, "status": "FAILED",
                                    "response_code": response.status_code, "error": response.text})

            except requests.RequestException as e:
                logger.error("ONOS request error for %s: %s", device_id, e)
                results.append({"device": device_id, "status": "ERROR", "error": str(e)})

        successful = sum(1 for r in results if r["status"] == "SUCCESS")

        return {
            "deployment_summary": {
                "total_rules": len(policy["flow_rules"]),
                "successful":  successful,
                "failed":      len(policy["flow_rules"]) - successful,
                "deployed_at": datetime.now(timezone.utc).isoformat(),
            },
            "rule_details":   results,
            "policy_applied": policy["policy_metadata"],
        }

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------
    def process_alert(self, alert: Dict) -> Dict:
        """
        Full mitigation pipeline:
          1. Extract intelligence from alert JSON
          2. Score threat with rule-based analysis
          3. Generate ONOS flow policy
          4. Deploy policy to ONOS controller
        """
        start = time.time()
        alert_id = alert.get("alert_id", "?")

        logger.info("Processing alert #%s", alert_id)

        try:
            # Step 1: Extract intelligence
            intel = self.extract_attack_intelligence(alert)
            logger.info("Alert #%s - attacker: %s, victim: %s, FC: %s (%s), confidence: %s",
                        alert_id, intel["attacker_ip"], intel["victim_ip"],
                        intel["function_code"], intel["function_description"],
                        intel["confidence"])

            # Step 2: Rule-based analysis
            analysis = self.rule_based_analysis(intel)
            logger.info("Alert #%s - threat: %s, recommendation: %s, score: %s",
                        alert_id, analysis["threat_level"],
                        analysis["policy_recommendation"],
                        analysis["confidence_score"])

            for step in analysis["reasoning_steps"]:
                logger.debug("  Reasoning: %s", step)

            # Step 3: Generate ONOS policy
            policy = self.generate_onos_policy(intel, analysis)
            logger.info("Alert #%s - policy scope: %s, target switch: %s",
                        alert_id, policy["deployment_strategy"]["scope"],
                        policy["deployment_strategy"]["target_switches"])

            # Step 4: Deploy to ONOS
            deployment = self.deploy_policy_to_onos(policy)
            elapsed = round(time.time() - start, 2)

            summary = deployment["deployment_summary"]
            if summary["failed"] == 0:
                logger.info("Alert #%s - mitigation deployed in %ss (%d/%d rules)",
                            alert_id, elapsed, summary["successful"], summary["total_rules"])
                status = "SUCCESS"
            else:
                logger.warning("Alert #%s - partial deployment in %ss (%d/%d rules failed)",
                               alert_id, elapsed, summary["failed"], summary["total_rules"])
                status = "PARTIAL_FAILURE"

            return {
                "execution_summary": {
                    "alert_id":               alert_id,
                    "execution_time_seconds": elapsed,
                    "status":                 status,
                    "timestamp":              datetime.now(timezone.utc).isoformat(),
                    "analysis_method":        "RULE_BASED",
                },
                "attack_intelligence": intel,
                "threat_analysis":     analysis,
                "policy_generated":    policy["policy_metadata"],
                "deployment_result":   deployment,
            }

        except Exception as e:
            logger.error("Alert #%s - pipeline error: %s", alert_id, e)
            return {
                "execution_summary": {
                    "alert_id": alert_id,
                    "status":   "PIPELINE_FAILURE",
                    "error":    str(e),
                    "execution_time_seconds": round(time.time() - start, 2),
                }
            }


# ===========================================================================
# SECTION 2: GROUPED DNP3 DETECTOR
# Handles: dual tshark monitoring, event grouping, alert generation,
#          and calling the policy engine for mitigation.
# ===========================================================================

class GroupedDNP3Detector:
    """
    Monitors live tshark output on DNP3 ports 20002-20024.
    Groups attack commands with victim responses before generating alerts.
    Calls DNP3PolicyEngine to deploy ONOS mitigation on each confirmed attack.
    """

    ADMIN_FUNCTION_CODES = {13, 14, 18, 21}

    FC_DESCRIPTIONS = {
        13:  "Cold Restart",
        14:  "Warm Restart",
        18:  "Stop Application",
        21:  "Disable Unsolicited",
        130: "Unsolicited Response",
    }

    STATION_ROLES = {
        "10.0.0.1": "master",
        **{f"10.0.0.{i}": "outstation" for i in range(2, 25)},
    }

    def __init__(self, onos_ip: str = "127.0.0.1", onos_port: str = "8181",
                 grouping_window: float = 0.5, dedup_window: int = 1):
        self.running         = False
        self.master_ip       = "10.0.0.1"
        self.alert_counter   = 1
        self.grouping_window = grouping_window  # seconds to accumulate related events
        self.dedup_window    = dedup_window     # seconds before re-alerting same pair

        # Grouping state
        self.attack_events   = {}   # (attacker_ip, victim_ip) -> event_info
        self.attack_sessions = {}   # session key -> session info
        self.recent_alerts   = {}   # (attacker_ip, victim_ip) -> last alert time

        # Policy engine - handles mitigation
        self.policy_engine = DNP3PolicyEngine(onos_ip=onos_ip, onos_port=onos_port)

        logger.info("Detector initialized - grouping window: %ss, dedup window: %ss",
                    grouping_window, dedup_window)

    # ------------------------------------------------------------------
    # Packet parsing helpers
    # ------------------------------------------------------------------
    def extract_function_code(self, payload_hex: str) -> Optional[int]:
        """Extract DNP3 function code from raw TCP payload hex string."""
        if not payload_hex or len(payload_hex) < 20:
            return None
        try:
            if not payload_hex.startswith('0564'):
                return None

            # Try common byte positions for the function code field
            for pos in (24, 22, 26, 20, 28):
                if len(payload_hex) > pos + 1:
                    try:
                        fc = int(payload_hex[pos:pos + 2], 16)
                        if fc in self.ADMIN_FUNCTION_CODES or fc in (0, 1, 129, 130):
                            return fc
                    except (ValueError, IndexError):
                        continue

            # Fallback: scan full payload for admin function codes
            for i in range(4, len(payload_hex) - 2, 2):
                try:
                    fc = int(payload_hex[i:i + 2], 16)
                    if fc in self.ADMIN_FUNCTION_CODES:
                        return fc
                except (ValueError, IndexError):
                    continue

        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------
    def should_alert(self, attacker_ip: str, victim_ip: str) -> bool:
        """Return True if enough time has passed since the last alert for this pair."""
        now = datetime.now()
        key = (attacker_ip, victim_ip)

        if key in self.recent_alerts:
            if (now - self.recent_alerts[key]).total_seconds() < self.dedup_window:
                return False

        self.recent_alerts[key] = now

        # Clean up stale dedup entries
        cutoff = now - timedelta(seconds=self.dedup_window * 2)
        self.recent_alerts = {k: v for k, v in self.recent_alerts.items() if v > cutoff}
        return True

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------
    def track_attack_session(self, src_ip: str, dst_ip: str, fc: int) -> Dict:
        """Track cumulative statistics for an attacker -> victim session."""
        key = f"{src_ip}->{dst_ip}"
        now = datetime.now()

        if key not in self.attack_sessions:
            self.attack_sessions[key] = {
                "first_seen":      now,
                "last_seen":       now,
                "attack_count":    0,
                "response_count":  0,
                "function_codes":  set(),
            }

        session = self.attack_sessions[key]
        session["last_seen"] = now
        session["function_codes"].add(fc)

        if fc in self.ADMIN_FUNCTION_CODES:
            session["attack_count"] += 1
        elif fc == 130:
            session["response_count"] += 1

        return session

    # ------------------------------------------------------------------
    # Event grouping
    # ------------------------------------------------------------------
    def add_attack_event(self, timestamp: str, src_ip: str, dst_ip: str,
                         dst_port: int, fc: int, event_type: str):
        """Buffer an event and schedule finalization after grouping_window seconds."""
        now = datetime.now()

        if fc in self.ADMIN_FUNCTION_CODES:
            attack_key     = (src_ip, dst_ip)
            is_attack_cmd  = True
        elif fc == 130 and dst_ip != self.master_ip:
            attack_key     = (dst_ip, src_ip)  # reverse: key is always attacker->victim
            is_attack_cmd  = False
        else:
            return

        if attack_key not in self.attack_events:
            self.attack_events[attack_key] = {
                "attacker_ip":     attack_key[0],
                "victim_ip":       attack_key[1],
                "created_time":    now,
                "attack_command":  None,
                "victim_responses": [],
                "session":         None,
            }

        event = self.attack_events[attack_key]

        if is_attack_cmd:
            event["attack_command"] = {
                "timestamp":     timestamp,
                "function_code": fc,
                "dst_port":      dst_port,
                "event_type":    event_type,
            }
            event["session"] = self.track_attack_session(src_ip, dst_ip, fc)
        else:
            event["victim_responses"].append({
                "timestamp":     timestamp,
                "function_code": fc,
                "dst_port":      dst_port,
                "event_type":    event_type,
            })
            self.track_attack_session(src_ip, dst_ip, fc)

        # Schedule finalization after grouping window expires
        threading.Timer(
            self.grouping_window,
            self.finalize_attack_event,
            args=[attack_key]
        ).start()

    def finalize_attack_event(self, attack_key: tuple):
        """Called after grouping_window expires. Generates alert if attack command present."""
        if attack_key not in self.attack_events:
            return

        event = self.attack_events.pop(attack_key)

        if not event["attack_command"]:
            return

        if not self.should_alert(event["attacker_ip"], event["victim_ip"]):
            return

        self.generate_grouped_alert(event)

    # ------------------------------------------------------------------
    # Confidence calculation
    # ------------------------------------------------------------------
    def calculate_confidence(self, event: Dict) -> float:
        """Score detection confidence from 0.0 to 1.0 based on event context."""
        confidence = 0.0
        attacker_ip = event["attacker_ip"]
        victim_ip   = event["victim_ip"]
        cmd         = event["attack_command"]
        responses   = event["victim_responses"]

        # Base: outstation-to-outstation (not master-initiated)
        if (attacker_ip != self.master_ip and victim_ip != self.master_ip and
                attacker_ip.startswith("10.0.0.") and victim_ip.startswith("10.0.0.")):
            confidence += 0.6

        # Admin function code from non-master
        if cmd and cmd["function_code"] in self.ADMIN_FUNCTION_CODES:
            confidence += 0.3

        # Victim responded (correlation)
        if responses:
            confidence += 0.15
            if len(responses) > 1:
                confidence += 0.05

        # High-impact function codes
        if cmd and cmd["function_code"] in (13, 18):
            confidence += 0.05

        # Ongoing campaign
        session = event.get("session", {})
        if session.get("attack_count", 0) > 1:
            confidence += 0.05

        return min(confidence, 1.0)

    # ------------------------------------------------------------------
    # Alert generation and mitigation trigger
    # ------------------------------------------------------------------
    def generate_grouped_alert(self, event: Dict):
        """Build alert JSON, print it, and invoke the policy engine for mitigation."""
        confidence      = self.calculate_confidence(event)
        cmd             = event["attack_command"]
        responses       = event["victim_responses"]
        session         = event.get("session", {})
        attacker_station = event["attacker_ip"].split('.')[-1]
        victim_station   = event["victim_ip"].split('.')[-1]
        fc               = cmd["function_code"]
        fc_desc          = self.FC_DESCRIPTIONS.get(fc, f"FC {fc}")

        # Build explanation string
        explanation = (
            f"Lateral movement attack: outstation {attacker_station} sent "
            f"{fc_desc} to outstation {victim_station}."
        )
        if responses:
            explanation += f" Victim responded {len(responses)} time(s)."
            try:
                attack_ts   = float(cmd["timestamp"])
                delays_ms   = [int((float(r["timestamp"]) - attack_ts) * 1000)
                               for r in responses]
                avg_delay   = sum(delays_ms) / len(delays_ms)
                explanation += f" Avg response time: {avg_delay:.0f}ms."
            except Exception:
                pass
        else:
            explanation += " No victim response detected."

        if session.get("attack_count", 0) > 1:
            explanation += f" Part of ongoing campaign ({session['attack_count']} commands)."

        alert = {
            "alert_id": f"{self.alert_counter:03d}",
            "type":     "LATERAL_MOVEMENT_ATTACK",
            "time":     datetime.now(timezone.utc).isoformat(),
            "attack_summary": {
                "attacker_ip":       event["attacker_ip"],
                "attacker_station":  int(attacker_station),
                "victim_ip":         event["victim_ip"],
                "victim_station":    int(victim_station),
                "success_indicators": len(responses) > 0,
            },
            "attack_command": {
                "function_code":        fc,
                "function_description": fc_desc,
                "timestamp":            cmd["timestamp"],
                "target_port":          cmd["dst_port"],
            },
            "victim_responses": [
                {
                    "function_code": r["function_code"],
                    "timestamp":     r["timestamp"],
                    "source_port":   r["dst_port"],
                }
                for r in responses
            ],
            "confidence":  round(confidence, 2),
            "explanation": explanation,
            "session_context": {
                "unique_function_codes": list(session.get("function_codes", set())),
                "total_attacks_in_session": session.get("attack_count", 1),
            },
        }

        self.output_alert(alert)

        # Invoke rule-based mitigation
        logger.info("Triggering mitigation for alert #%s", alert["alert_id"])
        try:
            result = self.policy_engine.process_alert(alert)
            exec_summary = result.get("execution_summary", {})
            deploy_result = result.get("deployment_result", {})
            deploy_summary = deploy_result.get("deployment_summary", {})

            if exec_summary.get("status") == "SUCCESS":
                logger.info("Mitigation SUCCESS for alert #%s - %d rule(s) deployed",
                            alert["alert_id"], deploy_summary.get("successful", 0))
            else:
                logger.warning("Mitigation PARTIAL/FAILED for alert #%s - status: %s",
                               alert["alert_id"], exec_summary.get("status"))
        except Exception as e:
            logger.error("Mitigation pipeline error for alert #%s: %s",
                         alert["alert_id"], e)

        self.alert_counter += 1

    def output_alert(self, alert: Dict):
        """Print formatted alert to stdout and log a one-line summary."""
        print("\n" + "=" * 100)
        print(f"ATTACK ALERT #{alert['alert_id']}")
        print("=" * 100)
        print(json.dumps(alert, indent=2))
        print("=" * 100 + "\n")

        summary = alert["attack_summary"]
        cmd     = alert["attack_command"]
        logger.critical(
            "ALERT #%s: %s - station %s -> station %s "
            "(FC %s, responses: %d, success: %s, confidence: %s)",
            alert["alert_id"], alert["type"],
            summary["attacker_station"], summary["victim_station"],
            cmd["function_code"], len(alert["victim_responses"]),
            summary["success_indicators"], alert["confidence"],
        )

    # ------------------------------------------------------------------
    # Packet processors (called from tshark reader threads)
    # ------------------------------------------------------------------
    def process_raw_packet(self, line: str):
        """Parse a raw TCP tshark output line and add admin-command events to buffer."""
        try:
            fields = line.strip().split('\t')
            if len(fields) < 6:
                return

            timestamp   = fields[0]
            src_ip      = fields[1]
            dst_ip      = fields[2]
            dst_port    = int(fields[4]) if fields[4] else 0
            payload_hex = fields[5] if len(fields) > 5 else ""

            if not payload_hex:
                return

            fc = self.extract_function_code(payload_hex)
            if fc and fc in self.ADMIN_FUNCTION_CODES and src_ip != self.master_ip:
                self.add_attack_event(timestamp, src_ip, dst_ip, dst_port,
                                      fc, "ADMIN_COMMAND")

        except Exception as e:
            logger.debug("Raw packet parse error: %s", e)

    def process_dissected_packet(self, line: str):
        """Parse a DNP3-dissected tshark output line and add response events to buffer."""
        try:
            fields = line.strip().split('\t')
            if len(fields) < 6:
                return

            timestamp = fields[0]
            src_ip    = fields[1]
            dst_ip    = fields[2]
            dst_port  = int(fields[4]) if fields[4] else 0
            fc        = int(fields[5]) if fields[5] else 0

            if fc == 130 and dst_ip != self.master_ip:
                self.add_attack_event(timestamp, src_ip, dst_ip, dst_port,
                                      fc, "VICTIM_RESPONSE")

        except Exception as e:
            logger.debug("Dissected packet parse error: %s", e)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def cleanup_expired_events(self):
        """Remove buffered events that were never finalized (missed timer)."""
        now = datetime.now()
        expired = [k for k, v in self.attack_events.items()
                   if (now - v["created_time"]).total_seconds() > self.grouping_window * 2]
        for k in expired:
            del self.attack_events[k]

    def cleanup_old_sessions(self, max_age_minutes: int = 5):
        """Purge sessions not seen within max_age_minutes."""
        cutoff = datetime.now() - timedelta(minutes=max_age_minutes)
        stale  = [k for k, v in self.attack_sessions.items()
                  if v["last_seen"] < cutoff]
        for k in stale:
            del self.attack_sessions[k]

    # ------------------------------------------------------------------
    # Monitoring entry point
    # ------------------------------------------------------------------
    def start_monitoring(self):
        """
        Launch two tshark processes in background threads:
          - raw thread:        captures TCP payload hex for function code extraction
          - dissected thread:  uses tshark DNP3 dissector for confirmed FC fields
        Main thread runs a status loop.
        """
        self.running = True

        # Build decode-as flags for all DNP3 ports 20002-20024
        decode_flags = []
        for port in range(20002, 20025):
            decode_flags += ["-d", f"tcp.port=={port},dnp3"]

        raw_cmd = [
            "tshark", "-l", "-n", "-i", "any",
            "-f", "tcp portrange 20002-20024",
            "-Y", "tcp and frame.len > 60",
            "-T", "fields",
            "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.payload",
        ]

        dissected_cmd = [
            "tshark", "-l", "-n", "-i", "any",
            "-f", "tcp portrange 20002-20024",
        ] + decode_flags + [
            "-Y", "dnp3",
            "-T", "fields",
            "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.srcport",      "-e", "tcp.dstport",
            "-e", "dnp3.al.func",
        ]

        logger.info("Starting DNP3 attack detection on ports 20002-20024")
        logger.info("Grouping window: %ss | Dedup window: %ss",
                    self.grouping_window, self.dedup_window)

        def reader_thread(cmd: list, processor, name: str):
            """Generic tshark reader thread."""
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
            logger.info("%s thread started (PID %d)", name, process.pid)
            for line in iter(process.stdout.readline, ''):
                if not self.running:
                    break
                if line.strip():
                    processor(line)
            process.terminate()
            logger.info("%s thread stopped", name)

        raw_thread = threading.Thread(
            target=reader_thread,
            args=(raw_cmd, self.process_raw_packet, "RawCapture"),
            daemon=True
        )
        dissected_thread = threading.Thread(
            target=reader_thread,
            args=(dissected_cmd, self.process_dissected_packet, "DNP3Dissect"),
            daemon=True
        )

        raw_thread.start()
        dissected_thread.start()

        # Status loop
        cycle = 0
        try:
            while self.running:
                time.sleep(15)
                cycle += 1
                self.cleanup_expired_events()
                self.cleanup_old_sessions()
                logger.info(
                    "Status (cycle %d): alerts=%d, active_sessions=%d, pending_events=%d",
                    cycle, self.alert_counter - 1,
                    len(self.attack_sessions), len(self.attack_events)
                )
        except Exception as e:
            logger.error("Monitoring loop error: %s", e)

    def stop(self):
        logger.info("Stopping detector")
        self.running = False


# ===========================================================================
# SECTION 3: ENTRY POINT
# ===========================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="DNP3 Attack Detector with Rule-Based ONOS Mitigation"
    )
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--grouping-window", type=float, default=0.5,
                        help="Event grouping window in seconds (default: 0.5)")
    parser.add_argument("--dedup-window", type=int, default=1,
                        help="Alert deduplication window in seconds (default: 1)")
    parser.add_argument("--onos-ip", default="127.0.0.1",
                        help="ONOS controller IP (default: 127.0.0.1)")
    parser.add_argument("--onos-port", default="8181",
                        help="ONOS REST API port (default: 8181)")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Debug logging enabled")

    detector = GroupedDNP3Detector(
        onos_ip         = args.onos_ip,
        onos_port       = args.onos_port,
        grouping_window = args.grouping_window,
        dedup_window    = args.dedup_window,
    )

    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    finally:
        detector.stop()


if __name__ == "__main__":
    main()

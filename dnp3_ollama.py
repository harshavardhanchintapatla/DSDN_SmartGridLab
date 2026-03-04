#!/usr/bin/env python3
"""
DNP3 LLM Policy Integration System with Real Ollama Integration
Processes attack detection JSON and generates ONOS mitigation policies using actual LLM
"""

import json
import requests
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import sys
import argparse
import ollama
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DNP3_LLM_POLICY")

class DNP3LLMPolicyEngine:
    """Real LLM-powered DNP3 security policy generation and deployment"""
    
    def __init__(self, onos_ip="172.20.0.5", onos_port="8181", llm_model="llama3.1", ollama_url="http://localhost:11434", test_llm: bool = True):
        self.onos_ip = onos_ip
        self.onos_port = onos_port
        self.onos_auth = ("onos", "rocks")
        self.llm_model = llm_model
        self.ollama_url = ollama_url
        
        # Network topology mapping
        self.switch_mapping = {
            "s1": "of:0000000000000001",   # h1, h2
            "s2": "of:0000000000000002",   # h3, h4
            "s3": "of:0000000000000003",   # h5, h6
            "s4": "of:0000000000000004",   # h7, h8
            "s5": "of:0000000000000005",   # h9, h10
            "s6": "of:0000000000000006",   # h11, h12
            "s7": "of:0000000000000007",   # h13, h14
            "s8": "of:0000000000000008",   # h15, h16
            "s9": "of:0000000000000009",   # h17, h18
            "s10": "of:000000000000000a",  # h19, h20
            "s11": "of:000000000000000b",  # h21, h22
            "s12": "of:000000000000000c"   # h23, h24
        }
        
        # Host to switch mapping
        self.host_switch_map = {
            "10.0.0.1": "s1", "10.0.0.2": "s1",    # s1
            "10.0.0.3": "s2", "10.0.0.4": "s2",    # s2
            "10.0.0.5": "s3", "10.0.0.6": "s3",    # s3
            "10.0.0.7": "s4", "10.0.0.8": "s4",    # s4
            "10.0.0.9": "s5", "10.0.0.10": "s5",   # s5
            "10.0.0.11": "s6", "10.0.0.12": "s6",  # s6
            "10.0.0.13": "s7", "10.0.0.14": "s7",  # s7
            "10.0.0.15": "s8", "10.0.0.16": "s8",  # s8
            "10.0.0.17": "s9", "10.0.0.18": "s9",  # s9
            "10.0.0.19": "s10", "10.0.0.20": "s10", # s10
            "10.0.0.21": "s11", "10.0.0.22": "s11", # s11
            "10.0.0.23": "s12", "10.0.0.24": "s12"  # s12
                }
        
        # Function code severity mapping
        self.fc_severity = {
            13: "CRITICAL",   # Cold Restart
            18: "CRITICAL",   # Stop Application
            14: "HIGH",       # Warm Restart
            21: "HIGH",       # Disable Unsolicited
            130: "MEDIUM"     # Unsolicited Response
        }
        
        # Test LLM connection
        if test_llm:
            self._test_llm_connection()
        
        logger.info("DNP3 LLM Policy Engine initialized")
        logger.info(f"ONOS Controller: {self.onos_ip}:{self.onos_port}")
        logger.info(f"LLM Model: {self.llm_model} at {self.ollama_url}")
    
    def _test_llm_connection(self):
        """Test connection to Ollama LLM"""
        try:
            response = ollama.chat(
                model=self.llm_model,
                messages=[{
                    'role': 'user',
                    'content': 'Test connection. Reply with just: CONNECTION_OK'
                }],
                options={'temperature': 0.1}
            )
            if "CONNECTION_OK" in response['message']['content']:
                logger.info(f"✅ LLM connection successful: {self.llm_model}")
            else:
                logger.warning(f"⚠️ LLM responded but unexpected content: {response['message']['content'][:50]}")
        except Exception as e:
            logger.error(f"❌ LLM connection failed: {e}")
            logger.error("Will fall back to rule-based analysis if LLM fails")
    
    def extract_attack_intelligence(self, detection_json: Dict) -> Dict:
        """Extract and analyze attack intelligence from detection JSON"""
        
        attack_summary = detection_json.get("attack_summary", {})
        attack_command = detection_json.get("attack_command", {})
        victim_responses = detection_json.get("victim_responses", [])
        
        intelligence = {
            # Core identifiers
            "alert_id": detection_json.get("alert_id"),
            "attack_type": detection_json.get("type"),
            "timestamp": detection_json.get("time"),
            "confidence": detection_json.get("confidence", 0.0),
            
            # Attack details
            "attacker_ip": attack_summary.get("attacker_ip"),
            "attacker_station": attack_summary.get("attacker_station"),
            "victim_ip": attack_summary.get("victim_ip"),
            "victim_station": attack_summary.get("victim_station"),
            "success_indicators": attack_summary.get("success_indicators", False),
            
            # Technical details
            "function_code": attack_command.get("function_code"),
            "function_description": attack_command.get("function_description"),
            "target_port": attack_command.get("target_port"),
            "victim_response_count": len(victim_responses),
            
            # Network context
            "attacker_switch": self.host_switch_map.get(attack_summary.get("attacker_ip")),
            "victim_switch": self.host_switch_map.get(attack_summary.get("victim_ip")),
            "cross_switch_attack": self.host_switch_map.get(attack_summary.get("attacker_ip")) != 
                                 self.host_switch_map.get(attack_summary.get("victim_ip")),
            
            # Threat assessment
            "severity": self.fc_severity.get(attack_command.get("function_code"), "UNKNOWN"),
            "explanation": detection_json.get("explanation", "")
        }
        
        return intelligence
    
    def real_llm_threat_analysis(self, intelligence: Dict) -> Dict:
        """Real LLM-powered threat analysis using Ollama"""
        
        # Craft detailed prompt for the LLM
        prompt = f"""You are a cybersecurity expert specializing in industrial control systems (ICS/SCADA) security, specifically analyzing DNP3 protocol attacks.

ATTACK INTELLIGENCE:
- Alert ID: {intelligence['alert_id']}
- Attack Type: {intelligence['attack_type']}
- Attacker IP: {intelligence['attacker_ip']} (Station {intelligence['attacker_station']}) on network switch {intelligence['attacker_switch']}
- Victim IP: {intelligence['victim_ip']} (Station {intelligence['victim_station']}) on network switch {intelligence['victim_switch']}
- DNP3 Function Code: {intelligence['function_code']} ({intelligence['function_description']})
- Attack Success: {intelligence['success_indicators']}
- Victim Response Count: {intelligence['victim_response_count']}
- Cross-Switch Attack: {intelligence['cross_switch_attack']}
- Detection Confidence: {intelligence['confidence']}
- Explanation: {intelligence['explanation']}

DNP3 FUNCTION CODE CONTEXT:
- FC 13 (Cold Restart): CRITICAL - Forces complete system restart, causes downtime
- FC 18 (Stop Application): CRITICAL - Stops industrial processes, production halt
- FC 14 (Warm Restart): HIGH - Partial system restart, service disruption
- FC 21 (Disable Unsolicited): HIGH - Disables status reporting, blinds operators
- FC 130 (Unsolicited Response): MEDIUM - Status/data response, reconnaissance

THREAT ASSESSMENT CRITERIA:
1. Function Code Severity (Critical > High > Medium > Low)
2. Attack Success Indicators (multiple victim responses = successful attack)
3. Detection Confidence (higher confidence = more reliable)
4. Lateral Movement (cross-switch attacks are more dangerous)

Please analyze this attack and provide your assessment in this EXACT format:

REASONING:
[Step-by-step analysis of why this is dangerous]

THREAT_LEVEL: [CRITICAL/HIGH/MEDIUM/LOW]
POLICY_RECOMMENDATION: [IMMEDIATE_BLOCK/SELECTIVE_BLOCK/RATE_LIMIT/MONITOR]
CONFIDENCE_SCORE: [0.0-1.0]
EXPLANATION: [Brief summary of your decision]

Focus on industrial control system security implications."""

        try:
            logger.info(f"🧠 Querying {self.llm_model} for threat analysis...")
            start_time = time.time()
            
            response = ollama.chat(
                model=self.llm_model,
                messages=[{
                    'role': 'user',
                    'content': prompt
                }],
                options={
                    'temperature': 0.1,  # Low temperature for consistent analysis
                    'top_p': 0.9,
                    'num_ctx': 4096
                }
            )
            
            llm_time = time.time() - start_time
            logger.info(f"⚡ LLM response received in {llm_time:.2f} seconds")
            
            # Parse LLM response
            return self._parse_llm_response(response['message']['content'], llm_time)
            
        except Exception as e:
            logger.error(f"❌ LLM analysis failed: {e}")
            logger.info("🔄 Falling back to rule-based analysis...")
            return self._fallback_rule_based_analysis(intelligence)
    
    def _parse_llm_response(self, llm_content: str, llm_time: float) -> Dict:
        """Parse LLM natural language response into structured data"""
        
        try:
            # Extract structured information using regex
            threat_level_match = re.search(r'THREAT_LEVEL:\s*([A-Z]+)', llm_content)
            policy_match = re.search(r'POLICY_RECOMMENDATION:\s*([A-Z_]+)', llm_content)
            confidence_match = re.search(r'CONFIDENCE_SCORE:\s*([0-9.]+)', llm_content)
            explanation_match = re.search(r'EXPLANATION:\s*(.+)', llm_content)
            reasoning_match = re.search(r'REASONING:\s*(.*?)(?=THREAT_LEVEL:|$)', llm_content, re.DOTALL)
            
            # Extract reasoning steps
            reasoning_steps = []
            if reasoning_match:
                reasoning_text = reasoning_match.group(1).strip()
                # Split into logical steps
                steps = [step.strip() for step in reasoning_text.split('\n') if step.strip() and not step.strip().startswith('-')]
                reasoning_steps = [step for step in steps if len(step) > 10]  # Filter short lines
            
            threat_analysis = {
                "reasoning_steps": reasoning_steps,
                "threat_level": threat_level_match.group(1) if threat_level_match else "MEDIUM",
                "policy_recommendation": policy_match.group(1) if policy_match else "MONITOR",
                "confidence_score": float(confidence_match.group(1)) if confidence_match else 0.5,
                "explanation": explanation_match.group(1).strip() if explanation_match else "LLM analysis completed",
                "llm_model_used": self.llm_model,
                "llm_response_time": llm_time,
                "raw_llm_response": llm_content
            }
            
            logger.info(f"🎯 LLM Analysis: {threat_analysis['threat_level']} threat, {threat_analysis['policy_recommendation']} recommended")
            
            return threat_analysis
            
        except Exception as e:
            logger.error(f"❌ Failed to parse LLM response: {e}")
            logger.debug(f"Raw LLM content: {llm_content[:200]}...")
            
            # Return basic analysis if parsing fails
            return {
                "reasoning_steps": ["LLM response parsing failed, using basic assessment"],
                "threat_level": "MEDIUM",
                "policy_recommendation": "MONITOR", 
                "confidence_score": 0.3,
                "explanation": "Fallback analysis due to parsing error",
                "llm_model_used": self.llm_model,
                "llm_response_time": llm_time,
                "raw_llm_response": llm_content,
                "parsing_error": str(e)
            }
    
    def _fallback_rule_based_analysis(self, intelligence: Dict) -> Dict:
        """Fallback rule-based analysis if LLM fails"""
        
        logger.info("🔧 Using rule-based fallback analysis...")
        
        threat_analysis = {
            "reasoning_steps": [],
            "threat_level": "MEDIUM",
            "policy_recommendation": "MONITOR",
            "confidence_score": 0.5,
            "explanation": "",
            "llm_model_used": "FALLBACK_RULES",
            "llm_response_time": 0.0
        }
        
        # Step 1: Assess attack severity
        if intelligence["function_code"] in [13, 18]:  # Critical functions
            threat_analysis["reasoning_steps"].append(
                f"Function Code {intelligence['function_code']} ({intelligence['function_description']}) is CRITICAL - can cause system downtime"
            )
            severity_score = 0.4
        elif intelligence["function_code"] in [14, 21]:  # High impact functions
            threat_analysis["reasoning_steps"].append(
                f"Function Code {intelligence['function_code']} ({intelligence['function_description']}) is HIGH impact - disrupts operations"
            )
            severity_score = 0.3
        else:
            severity_score = 0.1
        
        # Step 2: Assess attack success
        if intelligence["success_indicators"] and intelligence["victim_response_count"] >= 5:
            threat_analysis["reasoning_steps"].append(
                f"Attack SUCCESS confirmed - {intelligence['victim_response_count']} victim responses received"
            )
            success_score = 0.3
        elif intelligence["victim_response_count"] >= 1:
            threat_analysis["reasoning_steps"].append(
                f"Partial attack success - {intelligence['victim_response_count']} victim responses"
            )
            success_score = 0.2
        else:
            success_score = 0.0
        
        # Step 3: Assess detection confidence
        confidence_score = intelligence["confidence"] * 0.2
        threat_analysis["reasoning_steps"].append(
            f"Detection confidence: {intelligence['confidence']} (very high)"
        )
        
        # Step 4: Assess lateral movement risk
        if intelligence["cross_switch_attack"]:
            threat_analysis["reasoning_steps"].append(
                f"LATERAL MOVEMENT detected - attacker on {intelligence['attacker_switch']}, victim on {intelligence['victim_switch']}"
            )
            lateral_score = 0.1
        else:
            lateral_score = 0.0
        
        # Calculate final threat score
        total_score = severity_score + success_score + confidence_score + lateral_score
        
        # Determine threat level and policy
        if total_score >= 0.8:
            threat_analysis["threat_level"] = "CRITICAL"
            threat_analysis["policy_recommendation"] = "IMMEDIATE_BLOCK"
            threat_analysis["explanation"] = "Critical threat requiring immediate containment (rule-based analysis)"
        elif total_score >= 0.6:
            threat_analysis["threat_level"] = "HIGH"
            threat_analysis["policy_recommendation"] = "SELECTIVE_BLOCK" 
            threat_analysis["explanation"] = "High-impact attack requiring targeted blocking (rule-based analysis)"
        elif total_score >= 0.4:
            threat_analysis["threat_level"] = "MEDIUM"
            threat_analysis["policy_recommendation"] = "RATE_LIMIT"
            threat_analysis["explanation"] = "Suspicious activity requiring traffic limiting (rule-based analysis)"
        else:
            threat_analysis["threat_level"] = "LOW"
            threat_analysis["policy_recommendation"] = "MONITOR"
            threat_analysis["explanation"] = "Low-risk activity requiring enhanced monitoring (rule-based analysis)"
        
        threat_analysis["confidence_score"] = total_score
        
        return threat_analysis
    
    def llm_threat_analysis(self, intelligence: Dict) -> Dict:
        """Main threat analysis method - tries LLM first, falls back to rules"""
        return self.real_llm_threat_analysis(intelligence)
    
    def generate_onos_policy(self, intelligence: Dict, threat_analysis: Dict) -> Dict:
        """Generate ONOS flow rule policy based on LLM analysis"""
        
        policy = {
            "policy_metadata": {
                "alert_id": intelligence["alert_id"],
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "threat_level": threat_analysis["threat_level"],
                "policy_type": threat_analysis["policy_recommendation"],
                "reasoning": threat_analysis["explanation"],
                "llm_model_used": threat_analysis.get("llm_model_used", "unknown"),
                "llm_response_time": threat_analysis.get("llm_response_time", 0.0)
            },
            "flow_rules": [],
            "deployment_strategy": {
                "target_switches": [],
                "priority": 40000,
                "duration": 600,  # 10 minutes
                "scope": "ATTACKER_SOURCE"
            }
        }
        
        attacker_ip = intelligence["attacker_ip"]
        attacker_switch = intelligence["attacker_switch"]
        target_device = self.switch_mapping[attacker_switch]
        
        if threat_analysis["policy_recommendation"] == "IMMEDIATE_BLOCK":
            # Complete IP blocking for critical threats
            flow_rule = {
                "priority": 45000,  # Higher priority for critical threats
                "isPermanent": False,
                "timeout": 1800,  # 30 minutes for critical threats
                "deviceId": target_device,
                "treatment": {"instructions": []},  # DROP
                "selector": {
                    "criteria": [
                        {"type": "ETH_TYPE", "ethType": "0x0800"},  # IPv4
                        {"type": "IPV4_SRC", "ip": f"{attacker_ip}/32"},
                        {"type": "IP_PROTO", "protocol": 6}  # TCP
                    ]
                }
            }
            policy["deployment_strategy"]["scope"] = "COMPLETE_IP_BLOCK"
            
        elif threat_analysis["policy_recommendation"] == "SELECTIVE_BLOCK":
            # Block only DNP3 lateral movement
            flow_rule = {
                "priority": 40000,
                "isPermanent": False,
                "timeout": 600,
                "deviceId": target_device,
                "treatment": {"instructions": []},  # DROP
                "selector": {
                    "criteria": [
                        {"type": "ETH_TYPE", "ethType": "0x0800"},
                        {"type": "IPV4_SRC", "ip": f"{attacker_ip}/32"},
                        {"type": "IP_PROTO", "protocol": 6},
                        {"type": "TCP_DST", "tcpPort": "20002-20024"}  # DNP3 ports only
                    ]
                }
            }
            policy["deployment_strategy"]["scope"] = "DNP3_LATERAL_MOVEMENT_BLOCK"
            
        else:
            # For lower threats, just monitor/rate limit
            flow_rule = {
                "priority": 30000,
                "isPermanent": False,
                "timeout": 300,
                "deviceId": target_device,
                "treatment": {
                    "instructions": [
                        {"type": "OUTPUT", "port": "CONTROLLER"}  # Send to controller for monitoring
                    ]
                },
                "selector": {
                    "criteria": [
                        {"type": "IPV4_SRC", "ip": f"{attacker_ip}/32"}
                    ]
                }
            }
            policy["deployment_strategy"]["scope"] = "ENHANCED_MONITORING"
        
        policy["flow_rules"].append(flow_rule)
        policy["deployment_strategy"]["target_switches"].append(target_device)
        
        return policy
    
    def deploy_policy_to_onos(self, policy: Dict) -> Dict:
        """Deploy generated policy to ONOS controller"""
        
        deployment_results = []
        
        for flow_rule in policy["flow_rules"]:
            try:
                url = f"http://{self.onos_ip}:{self.onos_port}/onos/v1/flows"
                payload = {"flows": [flow_rule]}
                
                appId = "org.onosproject.cli"
                origin = policy.get('policy_metadata', {}).get('origin')
                if origin == 'FALLBACK':
                    appId = "org.onosproject.fallback"
                elif origin == 'LLM_FINAL':
                    appId = "org.onosproject.llm"

                response = requests.post(
                    url,
                    json=payload,
                    auth=self.onos_auth,
                    params={"appId": appId},
                    timeout=10
                )
                
                if response.status_code in [200, 201]:
                    deployment_results.append({
                        "device": flow_rule["deviceId"],
                        "status": "SUCCESS",
                        "response_code": response.status_code,
                        "message": "Flow rule deployed successfully"
                    })
                    logger.info(f"✅ Policy deployed to {flow_rule['deviceId']}")
                else:
                    deployment_results.append({
                        "device": flow_rule["deviceId"],
                        "status": "FAILED",
                        "response_code": response.status_code,
                        "error": response.text
                    })
                    logger.error(f"❌ Failed to deploy to {flow_rule['deviceId']}: {response.text}")
                    
            except Exception as e:
                deployment_results.append({
                    "device": flow_rule["deviceId"],
                    "status": "ERROR",
                    "error": str(e)
                })
                logger.error(f"💥 Deployment error for {flow_rule['deviceId']}: {e}")
        
        return {
            "deployment_summary": {
                "total_rules": len(policy["flow_rules"]),
                "successful": len([r for r in deployment_results if r["status"] == "SUCCESS"]),
                "failed": len([r for r in deployment_results if r["status"] != "SUCCESS"]),
                "deployment_time": datetime.now(timezone.utc).isoformat()
            },
            "rule_details": deployment_results,
            "policy_applied": policy["policy_metadata"]
        }
        
    def _find_flows_matching_attacker(self, device_id: str, attacker_ip: str) -> List[Dict]:
        """Return list of flow dicts on device that contain IPV4_SRC == attacker_ip"""
        try:
            url = f"http://{self.onos_ip}:{self.onos_port}/onos/v1/flows/{device_id}"
            r = requests.get(url, auth=self.onos_auth, timeout=5)
            r.raise_for_status()
            flows = r.json().get('flows', [])
            matched = []
            for f in flows:
                for crit in f.get('selector', {}).get('criteria', []):
                    if crit.get('type') == 'IPV4_SRC' and attacker_ip in crit.get('ip', ''):
                        matched.append(f)
                        break
            return matched
        except Exception as e:
            logger.error(f"Error fetching flows for {device_id}: {e}")
            return []

    def _delete_flow(self, device_id: str, flow_id: str) -> bool:
        """Delete a flow by device + flow id. Return True on 2xx."""
        try:
            url = f"http://{self.onos_ip}:{self.onos_port}/onos/v1/flows/{device_id}/{flow_id}"
            r = requests.delete(url, auth=self.onos_auth, timeout=5)
            if r.status_code in (200, 204):
                logger.info(f"Deleted flow {flow_id} on {device_id}")
                return True
            else:
                logger.warning(f"Delete flow {flow_id} returned {r.status_code}: {r.text}")
                return False
        except Exception as e:
            logger.error(f"Failed to delete flow {flow_id} on {device_id}: {e}")
            return False

    def remove_fallback_flows_for_attacker(self, device_id: str, attacker_ip: str) -> Dict:
        """Find and delete fallback flows matching attacker IP. Returns summary.
        Only removes flows created by the fallback app (org.onosproject.fallback).
        """
        try:
            matched = self._find_flows_matching_attacker(device_id, attacker_ip)
        except Exception as e:
            logger.error(f"Error while searching for flows to remove: {e}")
            return {'checked': 0, 'deleted': 0, 'errors': [{'error': str(e)}]}

        results = {'checked': len(matched), 'deleted': 0, 'errors': []}
        for f in matched:
            fid = f.get('id')
            app = f.get('appId', '')
            # Only delete flows created by our fallback app
            if app != 'org.onosproject.fallback':
                logger.debug(f"Skipping flow {fid} (appId={app}) — not a fallback flow")
                continue
            try:
                ok = self._delete_flow(device_id, fid)
                if ok:
                    results['deleted'] += 1
                else:
                    results['errors'].append({'id': fid, 'error': 'delete_failed'})
            except Exception as e:
                results['errors'].append({'id': fid, 'error': str(e)})
        return results
    
    def process_detection_alert(self, detection_json: Dict) -> Dict:
        """Main processing pipeline: Detection → Real LLM Analysis → Policy → Deployment"""
        
        start_time = time.time()
        
        logger.info("🚨 " + "="*80)
        logger.info(f"🚨 PROCESSING ATTACK ALERT #{detection_json.get('alert_id')} with LLM")
        logger.info("🚨 " + "="*80)
        
        try:
            # Step 1: Extract attack intelligence
            logger.info("🔍 Extracting attack intelligence...")
            intelligence = self.extract_attack_intelligence(detection_json)
            logger.info(f"📊 Attack: {intelligence['attacker_ip']} → {intelligence['victim_ip']} "
                       f"(FC {intelligence['function_code']}, Confidence: {intelligence['confidence']})")
            
            # Step 2: Real LLM threat analysis
            logger.info(f"🧠 Performing LLM threat analysis using {self.llm_model}...")
            threat_analysis = self.llm_threat_analysis(intelligence)
            logger.info(f"⚖️  Threat Level: {threat_analysis['threat_level']}")
            logger.info(f"📋 Policy Recommendation: {threat_analysis['policy_recommendation']}")
            logger.info(f"💭 LLM Reasoning: {threat_analysis['explanation']}")
            logger.info(f"🤖 Model Used: {threat_analysis.get('llm_model_used', 'unknown')}")
            
            # Step 3: Generate ONOS policy
            logger.info("⚙️  Generating ONOS flow policy...")
            policy = self.generate_onos_policy(intelligence, threat_analysis)
            logger.info(f"🎯 Policy Type: {policy['deployment_strategy']['scope']}")
            logger.info(f"📡 Target Switch: {policy['deployment_strategy']['target_switches'][0]}")
            # If LLM recommends IMMEDIATE_BLOCK, ensure final longer timeout and the highest priority
            if threat_analysis.get('policy_recommendation') == 'IMMEDIATE_BLOCK':
                for fr in policy.get('flow_rules', []):
                    fr['timeout'] = 1800      # 30 minutes
                    fr['priority'] = 65000    # final highest priority (overrides fallback)
                policy.setdefault('policy_metadata', {})['origin'] = 'LLM_FINAL'

                # Optional: after deploying the LLM final policy, remove fallback flows (cleanup)
            logger.info("🚀 Deploying policy to ONOS controller (LLM final)...")
            start_deploy = time.time()
            deployment_result = self.deploy_policy_to_onos(policy)
            end_deploy = time.time()

            # Try: remove fallback flows for cleanliness (best-effort)
            try:
                # device id is first target switch in generated policy
                device = policy['deployment_strategy']['target_switches'][0]
                self.remove_fallback_flows_for_attacker(device, intelligence['attacker_ip'])
            except Exception:
                pass
            
            # Step 5: Generate execution report
            execution_time = time.time() - start_time
            
            final_result = {
                "execution_summary": {
                    "alert_id": intelligence["alert_id"],
                    "execution_time_seconds": round(execution_time, 2),
                    "status": "SUCCESS" if deployment_result["deployment_summary"]["failed"] == 0 else "PARTIAL_FAILURE",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "llm_analysis_method": threat_analysis.get("llm_model_used", "unknown")
                },
                "attack_intelligence": intelligence,
                "llm_analysis": threat_analysis,
                "policy_generated": policy["policy_metadata"],
                "deployment_result": deployment_result
            }
            
            logger.info("🚨 " + "="*80)
            if final_result["execution_summary"]["status"] == "SUCCESS":
                logger.info("✅ MITIGATION SUCCESSFULLY DEPLOYED WITH LLM")
            else:
                logger.warning("⚠️  PARTIAL DEPLOYMENT - CHECK ERRORS")
            logger.info(f"⏱️  Total execution time: {execution_time:.2f} seconds")
            logger.info(f"🧠 LLM response time: {threat_analysis.get('llm_response_time', 0):.2f} seconds")
            logger.info(f"📊 Rules deployed: {deployment_result['deployment_summary']['successful']}/{deployment_result['deployment_summary']['total_rules']}")
            logger.info("🚨 " + "="*80)
            
            return final_result
            
        except Exception as e:
            logger.error(f"💥 Pipeline execution failed: {e}")
            return {
                "execution_summary": {
                    "alert_id": detection_json.get("alert_id"),
                    "status": "PIPELINE_FAILURE",
                    "error": str(e),
                    "execution_time_seconds": time.time() - start_time
                }
            }

def main():
    """Main execution function"""
    
    parser = argparse.ArgumentParser(description='DNP3 LLM Policy Engine with Real Ollama Integration')
    parser.add_argument('--input', '-i', help='Input JSON file with detection alert')
    parser.add_argument('--json', '-j', help='Direct JSON string input')
    parser.add_argument('--onos-ip', default='13.217.164.96', help='ONOS controller IP')
    parser.add_argument('--llm-model', default='llama3.1', help='Ollama model to use')
    parser.add_argument('--ollama-url', default='http://localhost:11434', help='Ollama server URL')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize policy engine with real LLM
    engine = DNP3LLMPolicyEngine(
        onos_ip=args.onos_ip,
        llm_model=args.llm_model,
        ollama_url=args.ollama_url
    )
    
    # Get detection JSON
    if args.input:
        with open(args.input, 'r') as f:
            detection_json = json.load(f)
    elif args.json:
        detection_json = json.loads(args.json)
    else:
        # Use your actual detection example
        detection_json = {
            "alert_id": "003",
            "type": "LATERAL_MOVEMENT_ATTACK",
            "time": "2025-09-18T15:30:00.000000+00:00",
            "attack_summary": {
                "attacker_ip": "10.0.0.3",
                "attacker_station": 3,
                "victim_ip": "10.0.0.11",
                "victim_station": 11,
                "success_indicators": True
            },
            "attack_command": {
                "function_code": 18,
                "function_description": "Stop Application",
                "timestamp": "1757687035.665678137",
                "target_port": 20011
            },
            "victim_responses": [
                {"function_code": 130, "timestamp": "1757687035.663715395", "source_port": 38620},
                {"function_code": 130, "timestamp": "1757687035.665093205", "source_port": 38620},
                {"function_code": 130, "timestamp": "1757687035.665096589", "source_port": 38620},
                {"function_code": 130, "timestamp": "1757687035.665100544", "source_port": 38620},
                {"function_code": 130, "timestamp": "1757687035.665456065", "source_port": 38630},
                {"function_code": 130, "timestamp": "1757687035.665800637", "source_port": 38630}
            ],
            "confidence": 1.0,
            "explanation": "LLM TEST: Lateral movement attack using critical Stop Application command with confirmed success indicators.",
            "session_context": {
                "unique_function_codes": [18]
            }
        }
    
    # Process the detection alert
    result = engine.process_detection_alert(detection_json)
    
    # Output final results
    print("\n" + "="*80)
    print("🤖 LLM POLICY ENGINE EXECUTION RESULTS")
    print("="*80)
    print(json.dumps(result, indent=2))

def handle_alert(alert: dict, onos_ip: str = "13.217.164.96", llm_model: str = "llama3.1", ollama_url: str = "http://localhost:11434"):
    """Simple callable interface for detector integration"""
    try:
        engine = DNP3LLMPolicyEngine(onos_ip=onos_ip, llm_model=llm_model, ollama_url=ollama_url)
        result = engine.process_detection_alert(alert)
        return result
    except Exception as e:
        logger.error(f"handle_alert failed: {e}")
        return {"execution_summary": {"status": "FAILED", "error": str(e)}}

if __name__ == "__main__":
    main()
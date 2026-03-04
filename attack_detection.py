#!/usr/bin/env python3
"""
DNP3 Attack Detector with Alert Grouping
Groups related attack-response pairs into single alerts
"""

import subprocess
import json
import time
import logging
import importlib
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Set, List
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DNP3_GROUPED")

class GroupedDNP3Detector:
    """DNP3 detector that groups attack-response pairs into single alerts"""
    
    def __init__(self):
        self.running = False
        self.master_ip = "10.0.0.1"
        self.alert_counter = 1
        
        # Function code mappings
        self.admin_function_codes = {13, 14, 18, 21}
        self.fc_descriptions = {
            13: "Cold Restart",
            14: "Warm Restart", 
            18: "Stop Application",
            21: "Disable Unsolicited",
            130: "Unsolicited Response"
        }
        
        # Station role mapping
        self.station_roles = {
            "10.0.0.1": "master",
            **{f"10.0.0.{i}": "outstation" for i in range(2, 25)}
        }
        
        # Alert grouping - collect related events before generating alerts
        self.attack_events = {}  # Key: (attacker_ip, victim_ip) -> event_info
        self.attack_sessions = {}  # Track ongoing attack sessions
        self.grouping_window = 0.5  # seconds to wait and group related events
        self.dedup_window = 1  # seconds to prevent duplicate alerts
        self.recent_alerts = {}  # Track recent alerts for deduplication
        
        logger.info("Grouped DNP3 Attack Detector initialized")
        logger.info("Event grouping enabled - combining related attack-response pairs")
    
    def extract_function_code(self, payload_hex: str) -> Optional[int]:
        """Extract DNP3 function code from TCP payload"""
        if not payload_hex or len(payload_hex) < 20:
            return None
            
        try:
            if not payload_hex.startswith('0564'):
                return None
            
            # Multiple position attempts for function code
            positions = [24, 22, 26, 20, 28]
            
            for pos in positions:
                if len(payload_hex) > pos + 1:
                    try:
                        fc_hex = payload_hex[pos:pos+2]
                        fc_value = int(fc_hex, 16)
                        
                        # Return valid DNP3 function codes
                        if fc_value in self.admin_function_codes or fc_value in [0, 1, 129, 130]:
                            return fc_value
                    except (ValueError, IndexError):
                        continue
            
            # Fallback: scan for admin function codes
            for i in range(4, len(payload_hex) - 2, 2):
                try:
                    fc_hex = payload_hex[i:i+2]
                    fc_value = int(fc_hex, 16)
                    if fc_value in self.admin_function_codes:
                        return fc_value
                except (ValueError, IndexError):
                    continue
                    
        except Exception:
            pass
            
        return None
    
    def should_alert(self, attacker_ip: str, victim_ip: str) -> bool:
        """Check if we should generate an alert or if it's a recent duplicate"""
        current_time = datetime.now()
        alert_key = (attacker_ip, victim_ip)
        
        # Check if we've alerted for this attack pair recently
        if alert_key in self.recent_alerts:
            last_alert_time = self.recent_alerts[alert_key]
            if (current_time - last_alert_time).total_seconds() < self.dedup_window:
                return False  # Skip duplicate alert
        
        # Update the last alert time
        self.recent_alerts[alert_key] = current_time
        
        # Clean up old entries
        cutoff_time = current_time - timedelta(seconds=self.dedup_window * 2)
        self.recent_alerts = {k: v for k, v in self.recent_alerts.items() 
                             if v > cutoff_time}
        
        return True
    
    def track_attack_session(self, src_ip: str, dst_ip: str, function_code: int) -> Dict:
        """Track attack sessions to provide better context"""
        session_key = f"{src_ip}->{dst_ip}"
        current_time = datetime.now()
        
        if session_key not in self.attack_sessions:
            self.attack_sessions[session_key] = {
                "first_seen": current_time,
                "last_seen": current_time,
                "attack_count": 0,
                "response_count": 0,
                "function_codes": set()
            }
        
        session = self.attack_sessions[session_key]
        session["last_seen"] = current_time
        session["function_codes"].add(function_code)
        
        if function_code in self.admin_function_codes:
            session["attack_count"] += 1
        elif function_code == 130:
            session["response_count"] += 1
        
        return session
    
    def add_attack_event(self, timestamp: str, src_ip: str, dst_ip: str, 
                        dst_port: int, function_code: int, event_type: str):
        """Add an attack event to the grouping buffer"""
        current_time = datetime.now()
        
        # Determine the attack pair key (always attacker -> victim)
        if function_code in self.admin_function_codes:
            # This is an attack command
            attack_key = (src_ip, dst_ip)
            is_attack_command = True
        elif function_code == 130 and dst_ip != self.master_ip:
            # This is a response - reverse the key to match the attack
            attack_key = (dst_ip, src_ip)
            is_attack_command = False
        else:
            return  # Ignore other traffic
        
        # Initialize attack event if not exists
        if attack_key not in self.attack_events:
            self.attack_events[attack_key] = {
                "attacker_ip": attack_key[0],
                "victim_ip": attack_key[1],
                "created_time": current_time,
                "attack_command": None,
                "victim_responses": [],
                "session": None
            }
        
        event_info = self.attack_events[attack_key]
        
        # Add the event details
        if is_attack_command:
            event_info["attack_command"] = {
                "timestamp": timestamp,
                "function_code": function_code,
                "dst_port": dst_port,
                "event_type": event_type
            }
            # Track session for attack command
            event_info["session"] = self.track_attack_session(src_ip, dst_ip, function_code)
        else:
            event_info["victim_responses"].append({
                "timestamp": timestamp,
                "function_code": function_code,
                "dst_port": dst_port,
                "event_type": event_type
            })
            # Update session for response
            self.track_attack_session(src_ip, dst_ip, function_code)
        
        # Set timer to finalize this attack event
        threading.Timer(self.grouping_window, 
                       self.finalize_attack_event, 
                       args=[attack_key]).start()
    
    def finalize_attack_event(self, attack_key):
        """Generate final grouped alert for attack event"""
        if attack_key not in self.attack_events:
            return
        
        event_info = self.attack_events.pop(attack_key)
        
        # Only generate alert if there's an actual attack command
        if not event_info["attack_command"]:
            return
        
        # Check for deduplication
        if not self.should_alert(event_info["attacker_ip"], event_info["victim_ip"]):
            return
        
        self.generate_grouped_alert(event_info)
    
    def calculate_confidence(self, event_info: Dict) -> float:
        """Calculate confidence based on complete event information"""
        confidence = 0.0
        
        attacker_ip = event_info["attacker_ip"]
        victim_ip = event_info["victim_ip"]
        attack_cmd = event_info["attack_command"]
        responses = event_info["victim_responses"]
        
        # Base confidence for lateral movement
        if (attacker_ip != self.master_ip and victim_ip != self.master_ip and 
            attacker_ip.startswith("10.0.0.") and victim_ip.startswith("10.0.0.")):
            confidence += 0.6
        
        # Administrative function code from non-master
        if attack_cmd and attack_cmd["function_code"] in self.admin_function_codes:
            confidence += 0.3
        
        # Victim response correlation bonus
        if responses:
            confidence += 0.15
            # Multiple responses indicate successful attack
            if len(responses) > 1:
                confidence += 0.05
        
        # High-impact function codes
        if attack_cmd and attack_cmd["function_code"] in [13, 18]:
            confidence += 0.05
        
        # Session context
        session = event_info.get("session", {})
        if session.get("attack_count", 0) > 1:
            confidence += 0.05  # Part of campaign
        
        return min(confidence, 1.0)
    
    def dispatch_to_llm(self, alert: Dict):
        """Dispatch alert to LLM engine in background thread"""
        try:
            mod = importlib.import_module(self.llm_module)
            if not hasattr(mod, "handle_alert"):
                logger.error(f"LLM module {self.llm_module} missing handle_alert function")
                return
            
            # Run in thread to avoid blocking detection
            def _run_llm():
                try:
                    logger.info(f"Triggering LLM engine for alert #{alert['alert_id']}")
                    result = mod.handle_alert(
                        alert, 
                        onos_ip=self.onos_ip, 
                        llm_model=self.llm_model, 
                        ollama_url=self.ollama_url
                    )
                    
                    status = result.get('execution_summary', {}).get('status', 'UNKNOWN')
                    rules_deployed = result.get('deployment_result', {}).get('deployment_summary', {}).get('successful', 0)
                    
                    if status == "SUCCESS":
                        logger.info(f"LLM/ONOS SUCCESS for alert #{alert['alert_id']}: {rules_deployed} rules deployed")
                    else:
                        logger.error(f"LLM/ONOS FAILED for alert #{alert['alert_id']}: {status}")
                        
                except Exception as e:
                    logger.error(f"LLM processing failed for alert #{alert['alert_id']}: {e}")
            
            threading.Thread(target=_run_llm, daemon=True).start()
            
        except Exception as e:
            logger.error(f"Failed to import LLM module {self.llm_module}: {e}")
    
    def generate_grouped_alert(self, event_info: Dict):
        """Generate single comprehensive alert for grouped attack event"""
        confidence = self.calculate_confidence(event_info)
        
        attacker_station = event_info["attacker_ip"].split('.')[-1]
        victim_station = event_info["victim_ip"].split('.')[-1]
        attack_cmd = event_info["attack_command"]
        responses = event_info["victim_responses"]
        session = event_info.get("session", {})
        
        fc = attack_cmd["function_code"]
        fc_desc = self.fc_descriptions.get(fc, f"Function Code {fc}")
        
        # Create comprehensive explanation
        explanation = f"Lateral movement attack: Outstation {attacker_station} sent {fc_desc} command to outstation {victim_station}."
        
        if responses:
            explanation += f" Victim responded with {len(responses)} unsolicited response(s)."
            # Calculate response timing
            try:
                attack_time = float(attack_cmd["timestamp"])
                response_times = []
                for resp in responses:
                    resp_time = float(resp["timestamp"])
                    response_times.append(int((resp_time - attack_time) * 1000))
                
                if response_times:
                    avg_response = sum(response_times) / len(response_times)
                    explanation += f" Average response time: {avg_response:.0f}ms."
            except:
                pass
        else:
            explanation += " No victim response detected (attack may have failed)."
        
        # Add session context
        if session.get("attack_count", 0) > 1:
            explanation += f" Part of ongoing attack campaign ({session['attack_count']} commands sent)."
        
        # Create comprehensive alert
        alert = {
            "alert_id": f"{self.alert_counter:03d}",
            "type": "LATERAL_MOVEMENT_ATTACK",
            "time": datetime.now(timezone.utc).isoformat(),
            "attack_summary": {
                "attacker_ip": event_info["attacker_ip"],
                "attacker_station": int(attacker_station),
                "victim_ip": event_info["victim_ip"],
                "victim_station": int(victim_station),
                "success_indicators": len(responses) > 0
            },
            "attack_command": {
                "function_code": fc,
                "function_description": fc_desc,
                "timestamp": attack_cmd["timestamp"],
                "target_port": attack_cmd["dst_port"]
            },
            "victim_responses": [
                {
                    "function_code": resp["function_code"],
                    "timestamp": resp["timestamp"],
                    "source_port": resp["dst_port"]
                } for resp in responses
            ],
            "confidence": round(confidence, 2),
            "explanation": explanation,
            "session_context": {
                "unique_function_codes": list(session.get("function_codes", set()))
            }
        }
        
        self.output_alert(alert)
        
        try:
            logger.info(f"Running first-level fallback mitigation for alert #{alert.get('alert_id')}")
            # Import the engine (must be importable from detector location)
            from dnp3_ollama import DNP3LLMPolicyEngine

            # Instantiate engine for fallback ONLY (skip LLM connectivity test)
            engine = DNP3LLMPolicyEngine(onos_ip=self.onos_ip, llm_model=self.llm_model,
                                        ollama_url=self.ollama_url, test_llm=False)

            # Build intelligence & apply fallback (rule-based)
            intelligence = engine.extract_attack_intelligence(alert)
            # Use fallback rules to generate an immediate blocking policy
            fallback_analysis = engine._fallback_rule_based_analysis(intelligence)
            fallback_policy = engine.generate_onos_policy(intelligence, fallback_analysis)
            # You may want to adjust priority/timeout here within generate_onos_policy for fallback
            for fr in fallback_policy.get('flow_rules', []):
                fr['timeout'] = 300       # 300 seconds temporary block for fallback
                fr['priority'] = 60000     # high priority to ensure immediate blocking

            # Mark origin so deploy_policy_to_onos can set a different appId (optional but useful)
            fallback_policy.setdefault('policy_metadata', {})['origin'] = 'FALLBACK'
            start_deploy = time.time()
            fallback_deploy = engine.deploy_policy_to_onos(fallback_policy)
            end_deploy = time.time()
            mitigation_ts = datetime.now(timezone.utc).isoformat()

            # Attach fallback metadata to the alert for later correlation (helpful for LLM rollback)
            alert['fallback'] = {
                'deployed_at': mitigation_ts,
                'deploy_summary': fallback_deploy.get('deployment_summary', {}),
                'policy_metadata': fallback_policy.get('policy_metadata', {})
            }

            logger.info(f"Fallback deployed for alert #{alert.get('alert_id')}: {fallback_deploy['deployment_summary']}")
        except Exception as e:
            logger.error(f"Fallback mitigation failed for alert #{alert.get('alert_id')}: {e}")
        
        # STEP 6: Call LLM dispatch after outputting alert
        if getattr(self, "enable_llm", False):
            logger.info(f"Dispatching alert #{alert.get('alert_id')} to LLM for confirmation/upgrade/rollback")
            self.dispatch_to_llm(alert)
        else:
            logger.info(f"LLM disabled — fallback mitigation executed for alert #{alert.get('alert_id')}")
        
        self.alert_counter += 1
    
    def output_alert(self, alert: Dict):
        """Output single comprehensive grouped alert"""
        print("\n" + "="*100)
        print(f"GROUPED ATTACK EVENT #{alert['alert_id']}")
        if getattr(self, "enable_llm", False):
            print("(LLM POLICY ENGINE WILL BE TRIGGERED)")
        print("="*100)
        print(json.dumps(alert, indent=2))
        print("="*100 + "\n")
        
        # Log summary
        summary = alert['attack_summary']
        cmd = alert['attack_command']
        responses = len(alert['victim_responses'])
        
        logger.critical(f"ATTACK #{alert['alert_id']}: {alert['type']} - "
                       f"Station {summary['attacker_station']} -> Station {summary['victim_station']} "
                       f"(FC {cmd['function_code']}, {responses} responses, "
                       f"Success: {summary['success_indicators']}, Confidence: {alert['confidence']})")
    
    def process_raw_packet(self, line: str):
        """Process raw TCP packet and add to event grouping"""
        try:
            fields = line.strip().split('\t')
            if len(fields) < 6:
                return
            
            timestamp = fields[0]
            src_ip = fields[1]
            dst_ip = fields[2]
            src_port = int(fields[3]) if fields[3] else 0
            dst_port = int(fields[4]) if fields[4] else 0
            payload_hex = fields[5] if len(fields) > 5 else ""
            
            if not payload_hex:
                return
            
            function_code = self.extract_function_code(payload_hex)
            if not function_code:
                return
            
            # Add admin commands from non-master to grouping
            if function_code in self.admin_function_codes and src_ip != self.master_ip:
                self.add_attack_event(timestamp, src_ip, dst_ip, dst_port, 
                                    function_code, "ADMIN_COMMAND")
                
        except Exception as e:
            logger.debug(f"Raw packet processing error: {e}")
    
    def process_dissected_packet(self, line: str):
        """Process DNP3 dissected packets and add to event grouping"""
        try:
            fields = line.strip().split('\t')
            if len(fields) < 6:
                return
            
            timestamp = fields[0]
            src_ip = fields[1]
            dst_ip = fields[2]
            src_port = int(fields[3]) if fields[3] else 0
            dst_port = int(fields[4]) if fields[4] else 0
            function_code = int(fields[5]) if fields[5] else 0
            
            # Add unsolicited responses to non-master to grouping
            if function_code == 130 and dst_ip != self.master_ip:
                self.add_attack_event(timestamp, src_ip, dst_ip, dst_port, 
                                    function_code, "VICTIM_RESPONSE")
                
        except Exception as e:
            logger.debug(f"Dissected packet processing error: {e}")
    
    def cleanup_expired_events(self):
        """Clean up expired attack events"""
        current_time = datetime.now()
        expired_keys = []
        
        for key, event_info in self.attack_events.items():
            if (current_time - event_info["created_time"]).total_seconds() > self.grouping_window * 2:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.attack_events[key]
    
    def start_monitoring(self):
        """Start monitoring with event grouping"""
        self.running = True
        
        # Commands for dual monitoring
        raw_cmd = [
            "tshark", "-l", "-n", "-i", "any",
            "-f", "tcp portrange 20002-20024",
            "-Y", "tcp and frame.len > 60",
            "-T", "fields",
            "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.payload"
        ]
        
        dnp3_cmd = [
            "tshark", "-l", "-n", "-i", "any",
            "-f", "tcp portrange 20002-20024",
            "-d", "tcp.port==20002,dnp3", "-d", "tcp.port==20003,dnp3",
            "-d", "tcp.port==20004,dnp3", "-d", "tcp.port==20005,dnp3",
            "-d", "tcp.port==20006,dnp3", "-d", "tcp.port==20007,dnp3",
            "-d", "tcp.port==20008,dnp3", "-d", "tcp.port==20009,dnp3",
            "-d", "tcp.port==20010,dnp3", "-d", "tcp.port==20011,dnp3",
            "-d", "tcp.port==20012,dnp3", "-d", "tcp.port==20013,dnp3",
            "-d", "tcp.port==20014,dnp3", "-d", "tcp.port==20015,dnp3",
            "-d", "tcp.port==20016,dnp3", "-d", "tcp.port==20017,dnp3",
            "-d", "tcp.port==20018,dnp3", "-d", "tcp.port==20019,dnp3",
            "-d", "tcp.port==20020,dnp3", "-d", "tcp.port==20021,dnp3",
            "-d", "tcp.port==20022,dnp3", "-d", "tcp.port==20023,dnp3",
            "-d", "tcp.port==20024,dnp3",
            "-Y", "dnp3", "-T", "fields",
            "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "dnp3.al.func"
        ]
        
        logger.info("Starting grouped DNP3 attack detection...")
        logger.info(f"Event grouping window: {self.grouping_window} seconds")
        logger.info(f"Alert deduplication window: {self.dedup_window} seconds")
        logger.info(f"LLM Policy Engine: {'ENABLED' if getattr(self, 'enable_llm', False) else 'DISABLED'}")
        
        try:
            def monitor_raw():
                process = subprocess.Popen(raw_cmd, stdout=subprocess.PIPE, 
                                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
                for line in iter(process.stdout.readline, ''):
                    if not self.running:
                        break
                    if line.strip():
                        self.process_raw_packet(line)
                process.terminate()
            
            def monitor_dissected():
                process = subprocess.Popen(dnp3_cmd, stdout=subprocess.PIPE, 
                                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
                for line in iter(process.stdout.readline, ''):
                    if not self.running:
                        break
                    if line.strip():
                        self.process_dissected_packet(line)
                process.terminate()
            
            # Start monitoring threads
            raw_thread = threading.Thread(target=monitor_raw, daemon=True)
            dissected_thread = threading.Thread(target=monitor_dissected, daemon=True)
            
            raw_thread.start()
            dissected_thread.start()
            
            # Status loop with cleanup
            cycle = 0
            while self.running:
                time.sleep(15)
                cycle += 1
                
                # Cleanup expired events
                self.cleanup_expired_events()
                
                active_sessions = len(self.attack_sessions)
                pending_events = len(self.attack_events)
                total_alerts = self.alert_counter - 1
                
                logger.info(f"Detection active (cycle {cycle}) - "
                           f"{total_alerts} alerts, {active_sessions} sessions, "
                           f"{pending_events} pending events")
                
                # Clean up old sessions
                cutoff_time = datetime.now() - timedelta(minutes=5)
                old_sessions = [k for k, v in self.attack_sessions.items() 
                               if v["last_seen"] < cutoff_time]
                for session_key in old_sessions:
                    del self.attack_sessions[session_key]
                
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
    
    def stop(self):
        """Stop monitoring"""
        logger.info("Stopping grouped DNP3 detector...")
        self.running = False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Grouped DNP3 Attack Detector with LLM Integration')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--grouping-window', type=float, default=0.5, 
                       help='Event grouping window in seconds (default: 0.5)')
    parser.add_argument('--dedup-window', type=int, default=1, 
                       help='Alert deduplication window in seconds (default: 1)')
    
    # STEP 5: Add LLM CLI arguments
    parser.add_argument('--enable-llm', action='store_true', help='Enable LLM policy deployment')
    parser.add_argument('--onos-ip', default='172.20.0.5', help='ONOS controller IP')
    parser.add_argument('--llm-model', default='llama3.1', help='Ollama model')
    parser.add_argument('--ollama-url', default='http://localhost:11434', help='Ollama server URL')
    parser.add_argument('--llm-module', default='dnp3_ollama', help='Python module with LLM engine')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Debug logging enabled")
    
    detector = GroupedDNP3Detector()
    detector.grouping_window = args.grouping_window
    detector.dedup_window = args.dedup_window
    
    # STEP 6: Store LLM config on detector instance  
    detector.enable_llm = args.enable_llm
    detector.onos_ip = args.onos_ip
    detector.llm_model = args.llm_model
    detector.ollama_url = args.ollama_url
    detector.llm_module = args.llm_module
    
    if args.enable_llm:
        logger.info(f"LLM integration ENABLED - using {args.llm_module}")
    else:
        logger.info("LLM integration DISABLED")
    
    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    finally:
        detector.stop()

if __name__ == "__main__":
    main()
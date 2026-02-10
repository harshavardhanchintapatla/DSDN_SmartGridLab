#!/usr/bin/env python3
"""
Simplified DNP3 Outstation - Clean and Reliable
Based on your working diagnostic, this focuses on what actually works
Updated to support stations 2-24
"""
import argparse
import time
import logging
import sys
from dnp3_python.dnp3station.outstation import MyOutStation

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("OUTSTATION")

class SimpleDNP3Outstation:
    def __init__(self, station_id: int, port: int):
        self.station_id = station_id
        self.port = port
        self.outstation = None
        log.info(f"Initializing Outstation {station_id} on port {port}")

    def start(self) -> bool:
        """Start outstation with the configuration that actually works"""
        try:
            # Based on your diagnostic success, use the working pattern
            self.outstation = MyOutStation(
                port=self.port,
                outstation_id=self.station_id,
                master_id=1  # Master is always ID 1
            )
            
            # Verify configuration
            try:
                config = self.outstation.get_config()
                log.info(f"Outstation config: {config}")
                
                # Check if station ID is correctly set
                if hasattr(config, 'get') and 'outstation_id' in config:
                    actual_id = config['outstation_id']
                    if actual_id != self.station_id:
                        log.error(f"Station ID mismatch: expected {self.station_id}, got {actual_id}")
                        return False
                    log.info(f"✓ Station ID {self.station_id} configured correctly")
                
            except Exception as e:
                log.warning(f"Could not verify config: {e}")
            
            # Start the outstation
            self.outstation.start()
            log.info(f"✓ Outstation {self.station_id} started on port {self.port}")
            return True
            
        except Exception as e:
            log.error(f"Failed to start outstation {self.station_id}: {e}")
            return False

    def stop(self):
        """Stop the outstation"""
        try:
            if self.outstation:
                self.outstation.shutdown()
                log.info(f"Outstation {self.station_id} stopped")
        except Exception as e:
            log.error(f"Stop error: {e}")

    def is_connected(self) -> bool:
        """Check connection status"""
        try:
            if self.outstation:
                connected = self.outstation.is_connected
                return bool(connected() if callable(connected) else connected)
        except Exception:
            pass
        return False

    def get_stats(self):
        """Get channel statistics"""
        try:
            if self.outstation:
                stats = self.outstation.channel_statistic
                return stats() if callable(stats) else stats
        except Exception:
            return None

    def run(self):
        """Main execution loop"""
        if not self.start():
            log.error(f"Failed to start outstation {self.station_id}")
            sys.exit(1)

        log.info(f"Outstation {self.station_id} running. Press Ctrl+C to stop.")
        
        try:
            cycle = 0
            while True:
                time.sleep(10)
                cycle += 1
                
                connected = self.is_connected()
                status = "Connected" if connected else "Waiting"
                log.info(f"Status: {status} ({cycle * 10}s)")
                
                # Show stats every 30 seconds
                if cycle % 3 == 0:
                    stats = self.get_stats()
                    if stats:
                        log.info(f"Channel stats: {stats}")
                        
        except KeyboardInterrupt:
            log.info("Received interrupt signal")
        finally:
            self.stop()

def main():
    parser = argparse.ArgumentParser(description='Simplified DNP3 Outstation')
    parser.add_argument('--station-id', type=int, required=True,
                       help='Station ID (2-24)')
    parser.add_argument('--base-port', type=int, default=20000,
                       help='Base port (default: 20000)')
    
    args = parser.parse_args()
    
    # Validate station ID (updated for 24 hosts)
    if not (2 <= args.station_id <= 24):
        log.error("Station ID must be between 2 and 24")
        sys.exit(1)
    
    port = args.base_port + args.station_id
    
    log.info("=" * 50)
    log.info(f"Starting DNP3 Outstation {args.station_id}")
    log.info(f"Port: {port}")
    log.info(f"Expected connections from Master ID 1")
    log.info("=" * 50)
    
    outstation = SimpleDNP3Outstation(args.station_id, port)
    outstation.run()

if __name__ == "__main__":
    main()
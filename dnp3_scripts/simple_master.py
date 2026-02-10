#!/usr/bin/env python3
"""
Simplified Multi-Outstation Master - Clean and Reliable
Connects to all stations 2-24 by default, simplified threading
Updated for 24-host topology
"""
import argparse
import time
import logging
import sys
from dnp3_python.dnp3station.master import MyMaster

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("MULTI_MASTER")

class OutstationConnection:
    """Manages connection to a single outstation"""
    
    def __init__(self, station_id: int, base_port: int = 20000):
        self.station_id = station_id
        self.ip = f"10.0.0.{station_id}"
        self.port = base_port + station_id
        self.master = None
        self.connected = False
        self.poll_count = 0
        
    def connect(self) -> bool:
        """Connect to the outstation"""
        try:
            log.info(f"[Station {self.station_id}] Connecting to {self.ip}:{self.port}")
            
            self.master = MyMaster(
                outstation_ip=self.ip,
                port=self.port,
                master_id=1,                    # Master is always ID 1
                outstation_id=self.station_id  # Target specific station
            )
            
            self.master.start()
            time.sleep(1)  # Allow connection to establish
            
            # Check connection status
            connected_attr = self.master.is_connected
            self.connected = bool(connected_attr() if callable(connected_attr) else connected_attr)
            
            if self.connected:
                log.info(f"[Station {self.station_id}] Connected successfully")
            else:
                log.warning(f"[Station {self.station_id}] Connection failed")
                
            return self.connected
            
        except Exception as e:
            log.error(f"[Station {self.station_id}] Connection error: {e}")
            self.connected = False
            return False
    
    def poll(self) -> bool:
        """Send a poll request to the outstation"""
        if not self.master or not self.connected:
            return False
            
        try:
            self.master.send_scan_all_request()
            self.poll_count += 1
            log.info(f"[Station {self.station_id}] Poll #{self.poll_count} sent")
            return True
            
        except Exception as e:
            log.error(f"[Station {self.station_id}] Poll error: {e}")
            self.connected = False
            return False
    
    def get_status(self) -> tuple:
        """Get connection status and statistics"""
        try:
            if not self.master:
                return False, None
                
            # Check current connection status
            connected_attr = self.master.is_connected
            is_connected = bool(connected_attr() if callable(connected_attr) else connected_attr)
            
            # Get statistics
            stats_attr = self.master.channel_statistic
            stats = stats_attr() if callable(stats_attr) else stats_attr
            
            self.connected = is_connected
            return is_connected, stats
            
        except Exception as e:
            return False, f"Status error: {e}"
    
    def disconnect(self):
        """Disconnect from the outstation"""
        try:
            if self.master:
                self.master.shutdown()
                log.info(f"[Station {self.station_id}] Disconnected")
        except Exception as e:
            log.error(f"[Station {self.station_id}] Disconnect error: {e}")

class SimplifiedMultiMaster:
    """Manages connections to multiple DNP3 outstations"""
    
    def __init__(self, station_ids: list, poll_interval: int = 15):
        self.station_ids = station_ids
        self.poll_interval = poll_interval
        self.connections = {}
        
        log.info(f"Initializing Multi-Master for stations: {station_ids}")
        log.info(f"Poll interval: {poll_interval} seconds")
    
    def connect_all(self) -> int:
        """Connect to all outstations"""
        log.info("Connecting to all outstations...")
        
        connected_count = 0
        
        for station_id in self.station_ids:
            connection = OutstationConnection(station_id)
            self.connections[station_id] = connection
            
            if connection.connect():
                connected_count += 1
            
            time.sleep(0.5)  # Small delay between connections
        
        log.info(f"Connected to {connected_count}/{len(self.station_ids)} outstations")
        return connected_count
    
    def poll_all(self) -> int:
        """Poll all connected outstations"""
        successful_polls = 0
        
        for station_id, connection in self.connections.items():
            if connection.connected and connection.poll():
                successful_polls += 1
                
        log.info(f"Successfully polled {successful_polls}/{len(self.connections)} stations")
        return successful_polls
    
    def show_status(self):
        """Display status of all connections"""
        print("\n" + "=" * 70)
        print(f"MASTER STATUS @ {time.strftime('%H:%M:%S')}")
        print("=" * 70)
        
        connected_count = 0
        
        for station_id in sorted(self.connections.keys()):
            connection = self.connections[station_id]
            is_connected, stats = connection.get_status()
            
            if is_connected:
                connected_count += 1
                
            status_icon = "🟢" if is_connected else "🔴"
            status_text = "Connected" if is_connected else "Disconnected"
            poll_info = f"(Polls: {connection.poll_count})"
            
            print(f"{status_icon} Station {station_id:2d} | {status_text:12s} | {poll_info:12s} | Stats: {stats}")
        
        print("-" * 70)
        print(f"Summary: {connected_count}/{len(self.connections)} stations connected")
        print("=" * 70)
    
    def disconnect_all(self):
        """Disconnect from all outstations"""
        log.info("Disconnecting from all outstations...")
        
        for connection in self.connections.values():
            connection.disconnect()
    
    def run(self):
        """Main execution loop"""
        # Connect to all outstations
        connected_count = self.connect_all()
        
        if connected_count == 0:
            log.error("No outstations connected. Check network and configurations.")
            return
        
        log.info("Starting polling loop. Press Ctrl+C to stop.")
        
        try:
            cycle = 0
            while True:
                cycle += 1
                log.info(f"\n--- Polling Cycle {cycle} ---")
                
                # Poll all stations
                self.poll_all()
                
                # Show detailed status every few cycles
                if cycle % 2 == 0:
                    self.show_status()
                
                # Wait for next cycle
                time.sleep(self.poll_interval)
                
        except KeyboardInterrupt:
            log.info("Received interrupt signal")
        finally:
            self.disconnect_all()

def main():
    parser = argparse.ArgumentParser(description='Simplified Multi-Outstation DNP3 Master')
    parser.add_argument('--stations', nargs='+', type=int, 
                       default=list(range(2, 25)),  # Default: stations 2-24 (updated)
                       help='List of outstation IDs to connect to (default: 2-24)')
    parser.add_argument('--poll-interval', type=int, default=15,
                       help='Polling interval in seconds (default: 15)')
    parser.add_argument('--base-port', type=int, default=20000,
                       help='Base port number (default: 20000)')
    
    args = parser.parse_args()
    
    # Validate station IDs (updated for 24 hosts)
    valid_stations = [s for s in args.stations if 2 <= s <= 24]
    if len(valid_stations) != len(args.stations):
        invalid = [s for s in args.stations if s not in valid_stations]
        log.warning(f"Ignoring invalid station IDs: {invalid}")
    
    if not valid_stations:
        log.error("No valid station IDs provided. Use stations 2-24.")
        sys.exit(1)
    
    log.info("=" * 70)
    log.info("STARTING MULTI-OUTSTATION DNP3 MASTER")
    log.info("=" * 70)
    log.info(f"Master ID: 1")
    log.info(f"Target Stations: {valid_stations}")
    log.info(f"Poll Interval: {args.poll_interval} seconds")
    log.info(f"Base Port: {args.base_port}")
    log.info("=" * 70)
    
    # Create and run the multi-master
    master = SimplifiedMultiMaster(valid_stations, args.poll_interval)
    master.run()

if __name__ == "__main__":
    main()
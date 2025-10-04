#!/usr/bin/env python3
'''
Modbus Fuzzer - Grammar-Based Modbus Fuzzer

Created on Apr 16, 2013 v0.1
Modified and added scanning function, Dec 14, 2013 v0.2
Added fuzzing feature for specific function code, Apr 30, 2014 v0.5
Major rewrite with grammar-based fuzzing, Oct 2025 v1.0

@author: Ali, TJ
'''
import socket
import sys
import struct
import time
import logging
import argparse
from datetime import datetime
from typing import List, Optional

# Import new grammar-based fuzzing components
try:
    from fuzzer_core import ModbusFuzzer, FuzzingStrategy
    from config_manager import ConfigManager, setup_logging
    from modbus_connection import ModbusConnection
    from modbus_packet import ModbusPacket
    from modbus_grammar import get_supported_function_codes
except ImportError as e:
    print(f"Error importing fuzzing modules: {e}")
    print("Make sure all required files are present:")
    print("- fuzzer_core.py")
    print("- config_manager.py")
    print("- modbus_connection.py")
    print("- modbus_packet.py")
    print("- modbus_grammar.py")
    sys.exit(1)

HOST = '127.0.0.1'    # The remote host
dest_port = 502       # The same port as used by the server
dumbflagset = 0
logging.basicConfig(filename='./fuzzer.log', filemode='a', level=logging.DEBUG, format='[%(asctime)s][%(levelname)s] %(message)s')


def create_connection(dest_ip, port):
    """Create socket connection to target - used by legacy scan function"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as msg:
        sys.stderr.write("[ERROR] %s\n" % str(msg))
        sys.exit(1)

    HOST = dest_ip
    try:
        sock.settimeout(0.5)
        sock.connect((HOST, dest_port))
    except socket.error as msg:
        logging.exception("Connection Failed!")
    else:
        logging.info("Connected to Server: %s" % dest_ip)

    return sock


def hexstr(s):
    """Convert bytes to hex string representation"""
    return '-'.join('%02x' % ord(c) for c in s)


def grammar_based_fuzzing(dest_ip: str, strategies: List[str] = None, function_codes: List[int] = None) -> None:
    """Grammar-based fuzzing using protocol specifications"""
    if strategies is None:
        strategies = ["grammar_based", "boundary_values"]
    
    # Convert string strategies to enum
    strategy_enums = []
    for strategy in strategies:
        if strategy == "grammar_based":
            strategy_enums.append(FuzzingStrategy.GRAMMAR_BASED)
        elif strategy == "boundary_values":
            strategy_enums.append(FuzzingStrategy.BOUNDARY_VALUES)
        elif strategy == "mutation":
            strategy_enums.append(FuzzingStrategy.MUTATION)
        elif strategy == "stress_test":
            strategy_enums.append(FuzzingStrategy.STRESS_TEST)
        elif strategy == "state_based":
            strategy_enums.append(FuzzingStrategy.STATE_BASED)
    
    print(f"Starting grammar-based fuzzing against {dest_ip}")
    print(f"Strategies: {strategies}")
    
    # Create fuzzer instance
    fuzzer = ModbusFuzzer(dest_ip, dest_port)
    
    try:
        # Run fuzzing session
        session = fuzzer.fuzz_all_function_codes(
            strategies=strategy_enums, 
            function_codes=function_codes
        )
        
        # Print summary
        summary = fuzzer.get_session_summary()
        print("\n=== Fuzzing Session Summary ===")
        print(f"Target: {summary['target']}")
        print(f"Duration: {summary['duration']:.2f} seconds")
        print(f"Total tests: {summary['total_tests']}")
        print(f"Success rate: {summary['success_rate']:.2%}")
        print(f"Interesting findings: {summary['interesting_findings']}")
        print(f"Unique responses: {summary['unique_responses']}")
        print(f"Function codes tested: {summary['function_codes_tested']}")
        
        # Save detailed report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"fuzzing_session_{timestamp}.json"
        fuzzer.save_session_report(report_file)
        print(f"\nDetailed report saved to: {report_file}")
        
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
    except Exception as e:
        logging.error(f"Fuzzing failed: {e}")
        print(f"Error during fuzzing: {e}")


def send_custom_packet(dest_ip: str, packet_hex: str) -> None:
    """Send a custom hex packet to target"""
    try:
        # Convert hex string to bytes
        hex_string = packet_hex.replace('-', '').replace(' ', '')
        packet_data = bytes.fromhex(hex_string)
        
        # Use connection manager
        connection = ModbusConnection(dest_ip, dest_port)
        success, response, response_time = connection.send_and_receive(packet_data)
        
        if success:
            print(f"Sent: {packet_hex}")
            if response:
                response_hex = '-'.join(f'{byte:02x}' for byte in response)
                print(f"Received: {response_hex}")
                print(f"Response time: {response_time:.3f}s")
            else:
                print("No response received")
        else:
            print("Failed to send packet")
            
    except Exception as e:
        print(f"Error sending custom packet: {e}")


def atod(a):
    """Convert ASCII IP to decimal"""
    return struct.unpack("!L", socket.inet_aton(a))[0]


def dtoa(d):
    """Convert decimal to ASCII IP"""
    return socket.inet_ntoa(struct.pack("!L", d))


def scan_device(ip_range):
    """Scan network range for Modbus devices"""
    net, _, mask = ip_range.partition('/')
    mask = int(mask)
    net = atod(net)
    
    print(f"Scanning {ip_range} for Modbus devices...")
    
    for dest_ip in (dtoa(net+n) for n in range(0, 1<<32-mask)):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as msg:
            sock.close()

        try:
            sock.settimeout(0.2)
            sock.connect((dest_ip, dest_port))
        except socket.error as msg:
            continue
        except socket.timeout:
            continue

        unitID = 0
        dataRecv = b''
        
        # Try to identify Modbus device
        while unitID < 10:  # Try first 10 unit IDs
            # Read holding registers request (FC 03)
            dataSend = struct.pack(">H", 0) + \
                       struct.pack(">H", 0) + \
                       struct.pack(">H", 6) + \
                       struct.pack(">B", unitID) + \
                       struct.pack(">B", 3) + \
                       struct.pack(">H", 0) + \
                       struct.pack(">H", 1)
            try:
                sock.send(dataSend)
            except socket.error:
                break

            try:
                dataRecv = sock.recv(1024)
            except socket.timeout:
                pass

            if len(dataRecv) > 0:
                print(f"Modbus device found at {dest_ip} (Unit ID: {unitID})")
                if dumbflagset == 1:
                    print('Starting grammar-based fuzzing...')
                    grammar_based_fuzzing(dest_ip)
                break
            else:
                unitID += 1
                
        sock.close()


def create_argument_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description='Modbus Fuzzer v1.0 - Grammar-Based Modbus Fuzzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Grammar-based fuzzing (recommended)
  python3 modFuzzer.py --grammar 192.168.1.100
  
  # Test specific function codes
  python3 modFuzzer.py --grammar 192.168.1.100 --functions 3,6,16
  
  # Use multiple strategies
  python3 modFuzzer.py --grammar 192.168.1.100 --strategies grammar_based,boundary_values,mutation
  
  # Send custom packet
  python3 modFuzzer.py --packet 192.168.1.100 0000000000060103000A0001
  
  # Scan network for devices
  python3 modFuzzer.py --scan 192.168.1.0/24

"""
    )
    
    # Main commands
    parser.add_argument('--grammar', '-g', dest='target_ip',
                       help='Grammar-based fuzzing')
    parser.add_argument('--packet', '-p', dest='packet_target',
                       help='Send custom hex packet')
    parser.add_argument('--scan', '-s', dest='scan_range',
                       help='Scan IP range for Modbus devices')
    parser.add_argument('--config', '-c', dest='config_file',
                       help='Configuration file path')
    
    # Fuzzing options
    parser.add_argument('--strategies', dest='strategies',
                       help='Comma-separated fuzzing strategies: grammar_based,boundary_values,mutation,stress_test,state_based')
    parser.add_argument('--functions', dest='function_codes',
                       help='Comma-separated function codes to test (e.g., 3,6,16)')
    parser.add_argument('--port', dest='port', type=int, default=502,
                       help='Target port (default: 502)')
    parser.add_argument('--timeout', dest='timeout', type=float, default=0.5,
                       help='Connection timeout (default: 0.5)')
    
    # Additional arguments
    parser.add_argument('packet_data', nargs='?', help='Packet data for custom packet mode')
    
    return parser


def main():
    """Main function"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Load configuration
    config_manager = ConfigManager(args.config_file)
    config = config_manager.load_config()
    
    # Setup logging
    setup_logging(config.logging)
    logger = logging.getLogger(__name__)
    
    # Override config with command line arguments
    if args.port:
        config.target.port = args.port
    if args.timeout:
        config.target.timeout = args.timeout
    
    global dest_port
    dest_port = config.target.port
    
    try:
        # Grammar-based fuzzing
        if args.target_ip:
            strategies = ['grammar_based', 'boundary_values']
            if args.strategies:
                strategies = [s.strip() for s in args.strategies.split(',')]
                
            function_codes = None
            if args.function_codes:
                function_codes = [int(fc.strip()) for fc in args.function_codes.split(',')]
                
            grammar_based_fuzzing(args.target_ip, strategies, function_codes)
            
        # Custom packet
        elif args.packet_target:
            if not args.packet_data:
                print("Error: Packet data required for custom packet mode")
                sys.exit(1)
            send_custom_packet(args.packet_target, args.packet_data)
            
        # Network scanning
        elif args.scan_range:
            scan_device(args.scan_range)
            
        else:
            # No command specified, show help
            parser.print_help()
            print("\nSupported function codes:")
            supported_codes = get_supported_function_codes()
            for fc in supported_codes:
                print(f"  {fc:02X} ({fc})")
            
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
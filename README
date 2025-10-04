# Modbus Fuzzer v1.0 - Grammar-Based Modbus Fuzzer

A rewritten Modbus fuzzer that uses protocol grammar for testing instead of brute forcing.

## Major Improvements in v1.0

### **Grammar-Based Fuzzing**
- **OLD**: Brute force 255^6 = 281,474,976,710,656 combinations with 6 nested loops
- **NEW**: Protocol-aware test case generation based on function code specifications

### **Test Generation**
- Complete Modbus protocol grammar for 15+ function codes
- Boundary value testing and edge case detection
- Mutation-based fuzzing of valid packets
- State-aware sequence testing

### **Modern Architecture**
- Python 3.7+ compatibility (migrated from Python 2)
- Object-oriented design with modular components
- Error handling and retry logic
- Structured logging with detailed reporting

### **Analysis Features**
- Response pattern recognition and classification
- Behavioral coverage tracking
- Finding detection and flagging
- JSON reports with full session analysis

### **Flexible Configuration**
- YAML configuration files
- Multiple fuzzing strategies
- Configurable timing and retry parameters
- Modern CLI with subcommands

## Quick Start

### Installation
```bash
# Clone repository
git clone https://github.com/AlixAbbasi/Modbus-Fuzzer.git
cd Modbus-Fuzzer

# Install dependencies (Python 3.7+)
pip3 install -r requirements.txt

# Optional: Install PyYAML for configuration support
pip3 install PyYAML
```

### Basic Usage
```bash
# Grammar-based fuzzing
python3 modFuzzer.py --grammar 192.168.1.100

# Test specific function codes
python3 modFuzzer.py --grammar 192.168.1.100 --functions 3,6,16

# Multiple strategies
python3 modFuzzer.py --grammar 192.168.1.100 --strategies grammar_based,boundary_values,mutation

# Send custom packet
python3 modFuzzer.py --packet 192.168.1.100 0000000000060103000A0001

# Scan network for devices
python3 modFuzzer.py --scan 192.168.1.0/24

# Custom configuration
python3 modFuzzer.py --grammar 192.168.1.100 --config my_config.yaml
```

## Fuzzing Strategies

1. **Grammar-Based**: Uses protocol grammar for valid packet generation
2. **Boundary Values**: Tests edge cases and boundary conditions  
3. **Mutation**: Mutates valid packets to find edge cases
4. **Stress Test**: High-volume testing for race conditions
5. **State-Based**: Tests sequences of operations

## Supported Function Codes

| Code | Name | Description |
|------|------|-------------|
| 01 | Read Coils | Read 1-2000 coil status |
| 02 | Read Discrete Inputs | Read 1-2000 input status |
| 03 | Read Holding Registers | Read 1-125 registers |
| 04 | Read Input Registers | Read 1-125 input registers |
| 05 | Write Single Coil | Write single coil |
| 06 | Write Single Register | Write single register |
| 08 | Diagnostics | Diagnostic functions |
| 15 | Write Multiple Coils | Write multiple coils |
| 16 | Write Multiple Registers | Write multiple registers |
| 20 | Read File Record | File record operations |
| 21 | Write File Record | File record operations |
| 23 | Read/Write Multiple Registers | Combined read/write |

## Configuration

Example `config.yaml`:
```yaml
target:
  host: "192.168.1.100"
  port: 502
  timeout: 0.5

fuzzing:
  strategies:
    - "grammar_based"
    - "boundary_values"
  max_tests_per_function: 1000
  delay_between_tests: 0.01

logging:
  level: "INFO"
  file_output: true
  log_file: "fuzzer.log"
```

## Output and Reporting

- **Console**: Real-time progress and summary
- **Log Files**: Detailed execution logs
- **JSON Reports**: Complete session analysis with findings
- **Statistics**: Coverage metrics and performance data

## Available Commands

```bash
# Grammar-based fuzzing
python3 modFuzzer.py --grammar <target_ip>

# Send custom hex packet  
python3 modFuzzer.py --packet <target_ip> <hex_packet>

# Scan network for Modbus devices
python3 modFuzzer.py --scan <ip_range>

# Show help and supported function codes
python3 modFuzzer.py --help
```

## Architecture

```
modFuzzer.py          # Main CLI interface
config.yaml           # Default configuration
config_manager.py     # Configuration handling
fuzzer_core.py        # Fuzzing engine
modbus_connection.py  # Connection management
modbus_grammar.py     # Protocol grammar definitions
modbus_packet.py      # Packet construction/parsing
requirements.txt      # Python dependencies
```

## Version History

- **v1.0** (2025): Complete rewrite with grammar-based fuzzing
- **v0.5** (2014): Added specific function code fuzzing
- **v0.2** (2013): Added scanning functionality
- **v0.1** (2013): Initial release

## Performance Comparison

| Metric | Old (v0.5) | New (v1.0) | Improvement |
|--------|------------|------------|-------------|
| Approach | Brute force loops | Grammar-based generation | Targeted testing |
| Packet validity | Most packets invalid | All packets valid | 100% valid packets |
| Test coverage | Random data patterns | Protocol-aware test cases | Systematic coverage |
| Setup complexity | Manual configuration | Automated with config files | Simplified setup |
| Analysis capability | Basic logging | Structured reporting | Detailed analysis |
| Python version | 2.x (deprecated) | 3.7+ | Modern compatibility |

## Contributing

This is a research tool for security testing. Please use responsibly and only on systems you own or have permission to test.

## License

Educational and research use only.

## Credits

- Original authors: Ali, TJ
- v1.0 rewrite: Grammar-based architecture and modern Python implementation

For more information visit: http://sigint.ir/blog/?p=14

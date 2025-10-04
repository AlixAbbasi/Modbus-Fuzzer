#!/usr/bin/env python3
"""
Modbus Packet Construction and Parsing
Smart packet building using grammar definitions instead of brute force
"""

import struct
import logging
from typing import Dict, List, Tuple, Any, Optional, Union
from dataclasses import dataclass
from modbus_grammar import (
    MODBUS_GRAMMAR, 
    FunctionCodeGrammar, 
    FieldDefinition, 
    ModbusDataType,
    get_function_grammar,
    is_valid_function_code,
    calculate_dependent_field_value,
    validate_field_value,
    get_interesting_values_for_field,
    INTERESTING_ADDRESSES
)

@dataclass
class ModbusResponse:
    """Represents a Modbus response packet"""
    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int
    function_code: int
    data: bytes
    is_exception: bool = False
    exception_code: Optional[int] = None
    raw_packet: bytes = b''
    response_time: float = 0.0

class ModbusPacket:
    """Smart Modbus packet construction using grammar definitions"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def build_packet(self, 
                    transaction_id: int,
                    protocol_id: int,
                    unit_id: int,
                    function_code: int,
                    field_values: Dict[str, Any],
                    variable_data: bytes = b'') -> bytes:
        """
        Build a Modbus TCP packet using grammar rules
        
        Args:
            transaction_id: Transaction identifier
            protocol_id: Protocol identifier (0 for Modbus)
            unit_id: Unit identifier
            function_code: Modbus function code
            field_values: Dictionary of field names to values
            variable_data: Additional variable-length data
            
        Returns:
            Complete Modbus TCP packet as bytes
        """
        if not is_valid_function_code(function_code):
            raise ValueError(f"Unsupported function code: {function_code}")
            
        grammar = get_function_grammar(function_code)
        if not grammar:
            raise ValueError(f"No grammar found for function code: {function_code}")
            
        # Build data section using grammar
        data_section = self._build_data_section(grammar, field_values, variable_data)
        
        # Calculate length (unit_id + function_code + data_section)
        length = 1 + 1 + len(data_section)
        
        # Build complete packet
        packet = (
            struct.pack(">H", transaction_id) +      # Transaction ID (2 bytes)
            struct.pack(">H", protocol_id) +         # Protocol ID (2 bytes)
            struct.pack(">H", length) +              # Length (2 bytes)
            struct.pack(">B", unit_id) +             # Unit ID (1 byte)
            struct.pack(">B", function_code) +       # Function Code (1 byte)
            data_section                              # Data (variable length)
        )
        
        self.logger.debug(f"Built packet for FC{function_code:02X}: {self.packet_to_hex(packet)}")
        return packet
    
    def _build_data_section(self, 
                           grammar: FunctionCodeGrammar, 
                           field_values: Dict[str, Any],
                           variable_data: bytes = b'') -> bytes:
        """Build the data section of a Modbus packet using grammar rules"""
        data_section = b''
        dependencies = {}
        
        # Process fixed fields in order
        for field in grammar.fixed_fields:
            if field.name not in field_values:
                raise ValueError(f"Missing required field: {field.name}")
                
            value = field_values[field.name]
            
            # Handle dependent fields (e.g., byte_count = quantity * 2)
            if field.depends_on:
                calculated_value = calculate_dependent_field_value(field, dependencies)
                if calculated_value > 0:
                    value = calculated_value
                    
            # Validate field value
            if not validate_field_value(field, value):
                self.logger.warning(f"Field {field.name} value {value} outside constraints")
                
            # Pack field based on data type
            if field.data_type == ModbusDataType.UINT8:
                data_section += struct.pack(">B", value & 0xFF)
            elif field.data_type == ModbusDataType.UINT16:
                data_section += struct.pack(">H", value & 0xFFFF)
            elif field.data_type == ModbusDataType.UINT32:
                data_section += struct.pack(">L", value & 0xFFFFFFFF)
                
            # Store for dependent field calculations
            dependencies[field.name] = value
            
        # Add variable data if present
        if grammar.variable_data and variable_data:
            data_section += variable_data
            
        return data_section
    
    def parse_response(self, raw_packet: bytes) -> Optional[ModbusResponse]:
        """
        Parse a Modbus TCP response packet
        
        Args:
            raw_packet: Raw response bytes
            
        Returns:
            ModbusResponse object or None if parsing fails
        """
        if len(raw_packet) < 8:  # Minimum Modbus TCP packet size
            self.logger.error(f"Packet too short: {len(raw_packet)} bytes")
            return None
            
        try:
            # Parse MBAP header
            transaction_id = struct.unpack(">H", raw_packet[0:2])[0]
            protocol_id = struct.unpack(">H", raw_packet[2:4])[0]
            length = struct.unpack(">H", raw_packet[4:6])[0]
            unit_id = struct.unpack(">B", raw_packet[6:7])[0]
            function_code = struct.unpack(">B", raw_packet[7:8])[0]
            
            # Extract data section
            data = raw_packet[8:] if len(raw_packet) > 8 else b''
            
            # Check for exception response (function code has high bit set)
            is_exception = (function_code & 0x80) != 0
            exception_code = None
            
            if is_exception:
                function_code = function_code & 0x7F  # Remove exception bit
                if len(data) >= 1:
                    exception_code = struct.unpack(">B", data[0:1])[0]
                    
            response = ModbusResponse(
                transaction_id=transaction_id,
                protocol_id=protocol_id,
                length=length,
                unit_id=unit_id,
                function_code=function_code,
                data=data,
                is_exception=is_exception,
                exception_code=exception_code,
                raw_packet=raw_packet
            )
            
            self.logger.debug(f"Parsed response: FC{function_code:02X}, Exception: {is_exception}")
            return response
            
        except Exception as e:
            self.logger.error(f"Failed to parse response: {e}")
            return None
    
    def generate_test_cases(self, function_code: int) -> List[Dict[str, Any]]:
        """
        Generate intelligent test cases for a function code using grammar
        
        Args:
            function_code: Modbus function code to generate tests for
            
        Returns:
            List of field value dictionaries for testing
        """
        if not is_valid_function_code(function_code):
            return []
            
        grammar = get_function_grammar(function_code)
        if not grammar:
            return []
            
        test_cases = []
        
        # Generate combinations of interesting values
        field_combinations = self._generate_field_combinations(grammar.fixed_fields)
        
        for combination in field_combinations:
            test_cases.append(combination)
            
        self.logger.info(f"Generated {len(test_cases)} test cases for FC{function_code:02X}")
        return test_cases
    
    def _generate_field_combinations(self, fields: List[FieldDefinition]) -> List[Dict[str, Any]]:
        """Generate combinations of interesting values for fields"""
        if not fields:
            return [{}]
            
        combinations = []
        
        # Special handling for address fields - use interesting addresses
        def get_field_values(field: FieldDefinition) -> List[int]:
            if 'address' in field.name.lower():
                # Use interesting addresses for address fields
                valid_addresses = []
                for addr in INTERESTING_ADDRESSES:
                    if validate_field_value(field, addr):
                        valid_addresses.append(addr)
                return valid_addresses if valid_addresses else [0]
            else:
                return get_interesting_values_for_field(field)
        
        # Generate combinations recursively
        def generate_recursive(field_index: int, current_combination: Dict[str, Any]):
            if field_index >= len(fields):
                combinations.append(current_combination.copy())
                return
                
            field = fields[field_index]
            field_values = get_field_values(field)
            
            for value in field_values:
                current_combination[field.name] = value
                generate_recursive(field_index + 1, current_combination)
                
        generate_recursive(0, {})
        
        # Limit combinations to prevent explosion
        max_combinations = 1000
        if len(combinations) > max_combinations:
            self.logger.warning(f"Too many combinations ({len(combinations)}), limiting to {max_combinations}")
            # Take evenly distributed samples
            step = len(combinations) // max_combinations
            combinations = combinations[::step][:max_combinations]
            
        return combinations
    
    def generate_variable_data_patterns(self, 
                                      grammar: FunctionCodeGrammar, 
                                      field_values: Dict[str, Any]) -> List[bytes]:
        """Generate patterns for variable-length data fields"""
        if not grammar.variable_data:
            return [b'']
            
        patterns = []
        
        # Determine expected data length from field values
        if 'byte_count' in field_values:
            expected_length = field_values['byte_count']
        elif 'quantity' in field_values:
            if grammar.function_code in [15]:  # Write Multiple Coils
                expected_length = (field_values['quantity'] + 7) // 8
            elif grammar.function_code in [16, 23]:  # Write Multiple Registers
                expected_length = field_values['quantity'] * 2
            else:
                expected_length = field_values['quantity']
        else:
            expected_length = 4  # Default
            
        # Generate different data patterns
        patterns.extend([
            b'\x00' * expected_length,           # All zeros
            b'\xFF' * expected_length,           # All ones
            b'\xAA' * expected_length,           # Alternating pattern
            b'\x55' * expected_length,           # Alternating pattern
            bytes(range(256))[:expected_length], # Incremental pattern
        ])
        
        # Add boundary length tests
        if expected_length > 1:
            patterns.extend([
                b'\xFF' * (expected_length - 1),    # One byte short
                b'\xFF' * (expected_length + 1),    # One byte long
            ])
            
        return patterns
    
    @staticmethod
    def packet_to_hex(packet: bytes) -> str:
        """Convert packet bytes to hex string for logging"""
        return '-'.join(f'{byte:02x}' for byte in packet)
    
    @staticmethod
    def hex_to_packet(hex_string: str) -> bytes:
        """Convert hex string to packet bytes"""
        hex_string = hex_string.replace('-', '').replace(' ', '')
        return bytes.fromhex(hex_string)
#!/usr/bin/env python3
"""
Modbus Protocol Grammar Definitions
Complete grammar rules for Modbus TCP function codes with field constraints and validation
"""

import struct
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum

class ModbusDataType(Enum):
    """Modbus data types for field validation"""
    UINT8 = "B"      # 1 byte unsigned
    UINT16 = "H"     # 2 bytes unsigned
    UINT32 = "L"     # 4 bytes unsigned
    BYTE_ARRAY = "s" # Variable length byte array

@dataclass
class FieldDefinition:
    """Definition of a field in Modbus data section"""
    name: str
    data_type: ModbusDataType
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    depends_on: Optional[str] = None  # Field that this field's value depends on
    multiplier: Optional[int] = None  # For calculated fields (e.g., byte_count = quantity * 2)

@dataclass
class FunctionCodeGrammar:
    """Complete grammar definition for a Modbus function code"""
    function_code: int
    name: str
    description: str
    fixed_fields: List[FieldDefinition]
    variable_data: Optional[FieldDefinition] = None
    min_data_length: int = 0
    max_data_length: int = 253  # Modbus maximum

# Core Modbus Grammar Definitions
MODBUS_GRAMMAR: Dict[int, FunctionCodeGrammar] = {
    # READ FUNCTION CODES
    1: FunctionCodeGrammar(
        function_code=1,
        name="Read Coils",
        description="Read 1 to 2000 contiguous coils status",
        fixed_fields=[
            FieldDefinition("start_address", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("quantity", ModbusDataType.UINT16, 1, 2000)
        ],
        min_data_length=4,
        max_data_length=4
    ),
    
    2: FunctionCodeGrammar(
        function_code=2,
        name="Read Discrete Inputs",
        description="Read 1 to 2000 contiguous discrete input status",
        fixed_fields=[
            FieldDefinition("start_address", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("quantity", ModbusDataType.UINT16, 1, 2000)
        ],
        min_data_length=4,
        max_data_length=4
    ),
    
    3: FunctionCodeGrammar(
        function_code=3,
        name="Read Holding Registers",
        description="Read 1 to 125 contiguous holding registers",
        fixed_fields=[
            FieldDefinition("start_address", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("quantity", ModbusDataType.UINT16, 1, 125)
        ],
        min_data_length=4,
        max_data_length=4
    ),
    
    4: FunctionCodeGrammar(
        function_code=4,
        name="Read Input Registers",
        description="Read 1 to 125 contiguous input registers",
        fixed_fields=[
            FieldDefinition("start_address", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("quantity", ModbusDataType.UINT16, 1, 125)
        ],
        min_data_length=4,
        max_data_length=4
    ),
    
    # WRITE FUNCTION CODES
    5: FunctionCodeGrammar(
        function_code=5,
        name="Write Single Coil",
        description="Write a single coil to either ON or OFF",
        fixed_fields=[
            FieldDefinition("address", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("value", ModbusDataType.UINT16, 0, 65535)  # 0x0000 or 0xFF00
        ],
        min_data_length=4,
        max_data_length=4
    ),
    
    6: FunctionCodeGrammar(
        function_code=6,
        name="Write Single Register",
        description="Write a single holding register",
        fixed_fields=[
            FieldDefinition("address", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("value", ModbusDataType.UINT16, 0, 65535)
        ],
        min_data_length=4,
        max_data_length=4
    ),
    
    # DIAGNOSTIC FUNCTION CODE
    8: FunctionCodeGrammar(
        function_code=8,
        name="Diagnostics",
        description="Diagnostic function with various sub-functions",
        fixed_fields=[
            FieldDefinition("sub_function", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("data", ModbusDataType.UINT16, 0, 65535)
        ],
        min_data_length=4,
        max_data_length=4
    ),
    
    # MULTIPLE WRITE FUNCTION CODES
    15: FunctionCodeGrammar(
        function_code=15,
        name="Write Multiple Coils",
        description="Write multiple coils",
        fixed_fields=[
            FieldDefinition("start_address", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("quantity", ModbusDataType.UINT16, 1, 1968),
            FieldDefinition("byte_count", ModbusDataType.UINT8, 1, 246, depends_on="quantity")
        ],
        variable_data=FieldDefinition("coil_values", ModbusDataType.BYTE_ARRAY),
        min_data_length=6,
        max_data_length=251
    ),
    
    16: FunctionCodeGrammar(
        function_code=16,
        name="Write Multiple Registers",
        description="Write multiple holding registers",
        fixed_fields=[
            FieldDefinition("start_address", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("quantity", ModbusDataType.UINT16, 1, 123),
            FieldDefinition("byte_count", ModbusDataType.UINT8, 2, 246, depends_on="quantity", multiplier=2)
        ],
        variable_data=FieldDefinition("register_values", ModbusDataType.BYTE_ARRAY),
        min_data_length=7,
        max_data_length=251
    ),
    
    # READ/WRITE FUNCTION CODE
    23: FunctionCodeGrammar(
        function_code=23,
        name="Read/Write Multiple Registers",
        description="Read and write multiple registers in one transaction",
        fixed_fields=[
            FieldDefinition("read_start_address", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("read_quantity", ModbusDataType.UINT16, 1, 125),
            FieldDefinition("write_start_address", ModbusDataType.UINT16, 0, 65535),
            FieldDefinition("write_quantity", ModbusDataType.UINT16, 1, 121),
            FieldDefinition("write_byte_count", ModbusDataType.UINT8, 2, 242, depends_on="write_quantity", multiplier=2)
        ],
        variable_data=FieldDefinition("write_register_values", ModbusDataType.BYTE_ARRAY),
        min_data_length=11,
        max_data_length=251
    ),
    
    # FILE TRANSFER FUNCTION CODES
    20: FunctionCodeGrammar(
        function_code=20,
        name="Read File Record",
        description="Read file record",
        fixed_fields=[
            FieldDefinition("byte_count", ModbusDataType.UINT8, 7, 245)
        ],
        variable_data=FieldDefinition("sub_requests", ModbusDataType.BYTE_ARRAY),
        min_data_length=8,
        max_data_length=246
    ),
    
    21: FunctionCodeGrammar(
        function_code=21,
        name="Write File Record",
        description="Write file record",
        fixed_fields=[
            FieldDefinition("request_data_length", ModbusDataType.UINT8, 9, 247)
        ],
        variable_data=FieldDefinition("sub_requests", ModbusDataType.BYTE_ARRAY),
        min_data_length=10,
        max_data_length=248
    ),
}

# Exception codes that can be returned
MODBUS_EXCEPTION_CODES = {
    1: "Illegal Function",
    2: "Illegal Data Address", 
    3: "Illegal Data Value",
    4: "Slave Device Failure",
    5: "Acknowledge",
    6: "Slave Device Busy",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed to Respond"
}

# Interesting values for fuzzing
INTERESTING_VALUES = {
    ModbusDataType.UINT8: [0, 1, 127, 128, 254, 255],
    ModbusDataType.UINT16: [0, 1, 255, 256, 32767, 32768, 65534, 65535],
    ModbusDataType.UINT32: [0, 1, 65535, 65536, 2147483647, 2147483648, 4294967294, 4294967295]
}

# Interesting addresses for testing
INTERESTING_ADDRESSES = [
    0,      # Start of memory
    1,      # Second address
    100,    # Common starting point
    40000,  # Common holding register area
    40001,  # Common holding register area
    50000,  # High address
    65534,  # Near end of address space
    65535   # End of address space
]

def get_supported_function_codes() -> List[int]:
    """Get list of all supported function codes"""
    return list(MODBUS_GRAMMAR.keys())

def get_function_grammar(function_code: int) -> Optional[FunctionCodeGrammar]:
    """Get grammar definition for a specific function code"""
    return MODBUS_GRAMMAR.get(function_code)

def is_valid_function_code(function_code: int) -> bool:
    """Check if function code is supported"""
    return function_code in MODBUS_GRAMMAR

def calculate_dependent_field_value(field: FieldDefinition, dependencies: Dict[str, int]) -> int:
    """Calculate value for fields that depend on other fields"""
    if field.depends_on and field.depends_on in dependencies:
        base_value = dependencies[field.depends_on]
        if field.multiplier:
            return base_value * field.multiplier
        return base_value
    return 0

def validate_field_value(field: FieldDefinition, value: int) -> bool:
    """Validate if a value is within the field's constraints"""
    if field.min_value is not None and value < field.min_value:
        return False
    if field.max_value is not None and value > field.max_value:
        return False
    return True

def get_interesting_values_for_field(field: FieldDefinition) -> List[int]:
    """Get interesting test values for a specific field"""
    base_values = INTERESTING_VALUES.get(field.data_type, [0, 1, 255, 65535])
    
    # Filter values based on field constraints
    valid_values = []
    for value in base_values:
        if validate_field_value(field, value):
            valid_values.append(value)
    
    # Add boundary values
    if field.min_value is not None:
        valid_values.extend([field.min_value, field.min_value + 1])
    if field.max_value is not None:
        valid_values.extend([field.max_value - 1, field.max_value])
    
    # Remove duplicates and sort
    return sorted(list(set(valid_values)))
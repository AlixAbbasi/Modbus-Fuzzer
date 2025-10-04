#!/usr/bin/env python3
"""
Grammar-Based Modbus Fuzzer Core
Intelligent fuzzing using protocol grammar instead of brute force
"""

import time
import logging
import json
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, asdict
from enum import Enum

from modbus_grammar import (
    MODBUS_GRAMMAR, 
    MODBUS_EXCEPTION_CODES,
    get_supported_function_codes,
    get_function_grammar
)
from modbus_packet import ModbusPacket, ModbusResponse
from modbus_connection import ModbusConnection

class FuzzingStrategy(Enum):
    """Different fuzzing strategies"""
    GRAMMAR_BASED = "grammar_based"      # Use grammar rules
    BOUNDARY_VALUES = "boundary_values"  # Focus on boundary conditions
    MUTATION = "mutation"                # Mutate valid packets
    STRESS_TEST = "stress_test"         # High-volume testing
    STATE_BASED = "state_based"         # Stateful sequence testing

@dataclass
class FuzzingResult:
    """Result of a single fuzzing test"""
    transaction_id: int
    function_code: int
    field_values: Dict[str, Any]
    sent_packet: bytes
    response: Optional[ModbusResponse]
    success: bool
    response_time: float
    timestamp: float
    error_message: Optional[str] = None
    is_interesting: bool = False  # Flagged for manual review

@dataclass
class FuzzingSession:
    """Complete fuzzing session results"""
    target_host: str
    target_port: int
    start_time: float
    end_time: Optional[float] = None
    total_tests: int = 0
    successful_tests: int = 0
    failed_tests: int = 0
    interesting_results: List[FuzzingResult] = None
    coverage_stats: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.interesting_results is None:
            self.interesting_results = []
        if self.coverage_stats is None:
            self.coverage_stats = {}

class ModbusFuzzer:
    """Intelligent Modbus fuzzer using grammar-based test generation"""
    
    def __init__(self, 
                 host: str, 
                 port: int = 502,
                 timeout: float = 0.5,
                 max_retries: int = 3):
        """
        Initialize the Modbus fuzzer
        
        Args:
            host: Target IP address
            port: Target port
            timeout: Connection timeout
            max_retries: Maximum retry attempts
        """
        self.host = host
        self.port = port
        self.connection = ModbusConnection(host, port, timeout, max_retries)
        self.packet_builder = ModbusPacket()
        self.logger = logging.getLogger(__name__)
        
        # Fuzzing state
        self.current_session: Optional[FuzzingSession] = None
        self.transaction_id = 0
        self.seen_responses: Set[str] = set()
        self.response_patterns: Dict[str, int] = defaultdict(int)
        self.function_code_coverage: Dict[int, int] = defaultdict(int)
        
        # Configuration
        self.delay_between_tests = 0.01  # 10ms default delay
        self.max_tests_per_function = 1000
        self.enable_response_analysis = True
        
    def start_fuzzing_session(self, strategies: List[FuzzingStrategy] = None) -> FuzzingSession:
        """
        Start a new fuzzing session
        
        Args:
            strategies: List of fuzzing strategies to use
            
        Returns:
            FuzzingSession object
        """
        if strategies is None:
            strategies = [FuzzingStrategy.GRAMMAR_BASED, FuzzingStrategy.BOUNDARY_VALUES]
            
        self.current_session = FuzzingSession(
            target_host=self.host,
            target_port=self.port,
            start_time=time.time()
        )
        
        self.logger.info(f"Starting fuzzing session against {self.host}:{self.port}")
        self.logger.info(f"Using strategies: {[s.value for s in strategies]}")
        
        # Reset state
        self.transaction_id = 0
        self.seen_responses.clear()
        self.response_patterns.clear()
        self.function_code_coverage.clear()
        
        return self.current_session
    
    def fuzz_all_function_codes(self, 
                               strategies: List[FuzzingStrategy] = None,
                               function_codes: List[int] = None) -> FuzzingSession:
        """
        Fuzz all supported function codes
        
        Args:
            strategies: Fuzzing strategies to use
            function_codes: Specific function codes to test (default: all)
            
        Returns:
            Complete fuzzing session results
        """
        session = self.start_fuzzing_session(strategies)
        
        if function_codes is None:
            function_codes = get_supported_function_codes()
            
        self.logger.info(f"Fuzzing {len(function_codes)} function codes")
        
        for function_code in function_codes:
            try:
                self.logger.info(f"Fuzzing function code {function_code:02X}")
                results = self.fuzz_function_code(function_code, strategies or [FuzzingStrategy.GRAMMAR_BASED])
                session.total_tests += len(results)
                session.successful_tests += sum(1 for r in results if r.success)
                session.failed_tests += sum(1 for r in results if not r.success)
                session.interesting_results.extend([r for r in results if r.is_interesting])
                
            except Exception as e:
                self.logger.error(f"Error fuzzing function code {function_code:02X}: {e}")
                
        return self.finish_session()
    
    def fuzz_function_code(self, 
                          function_code: int, 
                          strategies: List[FuzzingStrategy]) -> List[FuzzingResult]:
        """
        Fuzz a specific function code using given strategies
        
        Args:
            function_code: Modbus function code to test
            strategies: Fuzzing strategies to apply
            
        Returns:
            List of fuzzing results
        """
        results = []
        
        for strategy in strategies:
            strategy_results = self._execute_strategy(function_code, strategy)
            results.extend(strategy_results)
            
            # Track coverage
            self.function_code_coverage[function_code] += len(strategy_results)
            
            # Add delay between strategies
            if self.delay_between_tests > 0:
                time.sleep(self.delay_between_tests)
                
        return results
    
    def _execute_strategy(self, function_code: int, strategy: FuzzingStrategy) -> List[FuzzingResult]:
        """Execute a specific fuzzing strategy for a function code"""
        
        if strategy == FuzzingStrategy.GRAMMAR_BASED:
            return self._grammar_based_fuzzing(function_code)
        elif strategy == FuzzingStrategy.BOUNDARY_VALUES:
            return self._boundary_value_fuzzing(function_code)
        elif strategy == FuzzingStrategy.MUTATION:
            return self._mutation_fuzzing(function_code)
        elif strategy == FuzzingStrategy.STRESS_TEST:
            return self._stress_test_fuzzing(function_code)
        elif strategy == FuzzingStrategy.STATE_BASED:
            return self._state_based_fuzzing(function_code)
        else:
            self.logger.warning(f"Unknown strategy: {strategy}")
            return []
    
    def _grammar_based_fuzzing(self, function_code: int) -> List[FuzzingResult]:
        """Generate test cases using grammar rules"""
        results = []
        test_cases = self.packet_builder.generate_test_cases(function_code)
        
        self.logger.debug(f"Generated {len(test_cases)} grammar-based test cases for FC{function_code:02X}")
        
        for i, field_values in enumerate(test_cases):
            if i >= self.max_tests_per_function:
                break
                
            # Generate variable data patterns if needed
            grammar = get_function_grammar(function_code)
            if grammar and grammar.variable_data:
                data_patterns = self.packet_builder.generate_variable_data_patterns(grammar, field_values)
            else:
                data_patterns = [b'']
                
            for variable_data in data_patterns:
                result = self._execute_test_case(function_code, field_values, variable_data)
                results.append(result)
                
                # Add delay between tests
                if self.delay_between_tests > 0:
                    time.sleep(self.delay_between_tests)
                    
        return results
    
    def _boundary_value_fuzzing(self, function_code: int) -> List[FuzzingResult]:
        """Focus on boundary conditions and edge cases"""
        results = []
        grammar = get_function_grammar(function_code)
        
        if not grammar:
            return results
            
        # Generate boundary value test cases
        boundary_cases = self._generate_boundary_cases(grammar)
        
        for field_values in boundary_cases:
            result = self._execute_test_case(function_code, field_values)
            results.append(result)
            
            if self.delay_between_tests > 0:
                time.sleep(self.delay_between_tests)
                
        return results
    
    def _mutation_fuzzing(self, function_code: int) -> List[FuzzingResult]:
        """Mutate valid packets to find edge cases"""
        results = []
        
        # Start with a valid test case
        test_cases = self.packet_builder.generate_test_cases(function_code)
        if not test_cases:
            return results
            
        base_case = test_cases[0]
        
        # Generate mutations
        mutations = self._generate_mutations(base_case)
        
        for mutated_values in mutations:
            result = self._execute_test_case(function_code, mutated_values)
            results.append(result)
            
            if self.delay_between_tests > 0:
                time.sleep(self.delay_between_tests)
                
        return results
    
    def _stress_test_fuzzing(self, function_code: int) -> List[FuzzingResult]:
        """High-volume testing to trigger race conditions"""
        results = []
        test_cases = self.packet_builder.generate_test_cases(function_code)
        
        if not test_cases:
            return results
            
        # Use first test case for stress testing
        field_values = test_cases[0]
        
        # Send multiple rapid requests
        stress_count = min(100, self.max_tests_per_function)
        
        for i in range(stress_count):
            result = self._execute_test_case(function_code, field_values)
            results.append(result)
            
            # Minimal delay for stress testing
            time.sleep(0.001)
            
        return results
    
    def _state_based_fuzzing(self, function_code: int) -> List[FuzzingResult]:
        """Test sequences of operations to trigger state-dependent bugs"""
        results = []
        
        # Define common operation sequences
        sequences = [
            [6, 3],    # Write then read register
            [5, 1],    # Write then read coil
            [16, 3],   # Write multiple then read registers
            [15, 1],   # Write multiple then read coils
        ]
        
        for sequence in sequences:
            if function_code in sequence:
                # Execute the sequence
                for seq_fc in sequence:
                    test_cases = self.packet_builder.generate_test_cases(seq_fc)
                    if test_cases:
                        result = self._execute_test_case(seq_fc, test_cases[0])
                        results.append(result)
                        time.sleep(0.05)  # Small delay between sequence steps
                        
        return results
    
    def _execute_test_case(self, 
                          function_code: int, 
                          field_values: Dict[str, Any], 
                          variable_data: bytes = b'') -> FuzzingResult:
        """Execute a single test case"""
        self.transaction_id += 1
        timestamp = time.time()
        
        try:
            # Build packet
            packet = self.packet_builder.build_packet(
                transaction_id=self.transaction_id,
                protocol_id=0,
                unit_id=0,
                function_code=function_code,
                field_values=field_values,
                variable_data=variable_data
            )
            
            # Send packet and get response
            success, response_data, response_time = self.connection.send_and_receive(packet)
            
            # Parse response if received
            response = None
            if response_data:
                response = self.packet_builder.parse_response(response_data)
                
            # Create result
            result = FuzzingResult(
                transaction_id=self.transaction_id,
                function_code=function_code,
                field_values=field_values.copy(),
                sent_packet=packet,
                response=response,
                success=success,
                response_time=response_time,
                timestamp=timestamp
            )
            
            # Analyze response for interesting findings
            if self.enable_response_analysis:
                self._analyze_response(result)
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing test case: {e}")
            return FuzzingResult(
                transaction_id=self.transaction_id,
                function_code=function_code,
                field_values=field_values.copy(),
                sent_packet=b'',
                response=None,
                success=False,
                response_time=0.0,
                timestamp=timestamp,
                error_message=str(e)
            )
    
    def _analyze_response(self, result: FuzzingResult) -> None:
        """Analyze response to identify interesting findings"""
        if not result.response:
            return
            
        response = result.response
        
        # Create response signature for uniqueness tracking
        signature = f"{response.function_code}:{response.is_exception}:{response.exception_code}:{len(response.data)}"
        
        # Check if this is a new response pattern
        if signature not in self.seen_responses:
            self.seen_responses.add(signature)
            result.is_interesting = True
            self.logger.info(f"New response pattern: {signature}")
            
        # Track response patterns
        self.response_patterns[signature] += 1
        
        # Flag specific interesting conditions
        if response.is_exception:
            # Exception responses are always interesting
            result.is_interesting = True
            
        if response.response_time > 1.0:
            # Slow responses might indicate processing issues
            result.is_interesting = True
            self.logger.warning(f"Slow response: {response.response_time:.3f}s")
            
        if len(response.data) > 250:
            # Unusually large responses
            result.is_interesting = True
            self.logger.warning(f"Large response: {len(response.data)} bytes")
    
    def _generate_boundary_cases(self, grammar) -> List[Dict[str, Any]]:
        """Generate boundary value test cases"""
        boundary_cases = []
        
        # Basic boundary case - all minimum values
        min_case = {}
        max_case = {}
        
        for field in grammar.fixed_fields:
            if field.min_value is not None:
                min_case[field.name] = field.min_value
            if field.max_value is not None:
                max_case[field.name] = field.max_value
                
        if min_case:
            boundary_cases.append(min_case)
        if max_case:
            boundary_cases.append(max_case)
            
        return boundary_cases
    
    def _generate_mutations(self, base_case: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate mutations of a base test case"""
        mutations = []
        
        for field_name, value in base_case.items():
            # Bit flip mutations
            if isinstance(value, int):
                for bit in range(16):  # Assuming 16-bit values
                    mutated = value ^ (1 << bit)
                    mutated_case = base_case.copy()
                    mutated_case[field_name] = mutated & 0xFFFF
                    mutations.append(mutated_case)
                    
                # Arithmetic mutations
                for delta in [-1, 1, -256, 256]:
                    mutated = (value + delta) & 0xFFFF
                    mutated_case = base_case.copy()
                    mutated_case[field_name] = mutated
                    mutations.append(mutated_case)
                    
        return mutations
    
    def finish_session(self) -> FuzzingSession:
        """Finish the current fuzzing session"""
        if not self.current_session:
            raise RuntimeError("No active fuzzing session")
            
        self.current_session.end_time = time.time()
        self.current_session.coverage_stats = {
            'function_codes_tested': len(self.function_code_coverage),
            'total_unique_responses': len(self.seen_responses),
            'response_patterns': dict(self.response_patterns),
            'function_code_coverage': dict(self.function_code_coverage)
        }
        
        duration = self.current_session.end_time - self.current_session.start_time
        self.logger.info(f"Fuzzing session completed in {duration:.2f} seconds")
        self.logger.info(f"Total tests: {self.current_session.total_tests}")
        self.logger.info(f"Successful: {self.current_session.successful_tests}")
        self.logger.info(f"Failed: {self.current_session.failed_tests}")
        self.logger.info(f"Interesting findings: {len(self.current_session.interesting_results)}")
        
        return self.current_session
    
    def save_session_report(self, filename: str) -> None:
        """Save session results to JSON file"""
        if not self.current_session:
            raise RuntimeError("No active fuzzing session")
            
        # Convert session to serializable format
        session_dict = asdict(self.current_session)
        
        # Convert non-serializable objects
        for result in session_dict['interesting_results']:
            if result['sent_packet']:
                result['sent_packet'] = result['sent_packet'].hex()
            if result['response']:
                response = result['response']
                response['data'] = response['data'].hex() if response['data'] else ''
                response['raw_packet'] = response['raw_packet'].hex() if response['raw_packet'] else ''
                
        with open(filename, 'w') as f:
            json.dump(session_dict, f, indent=2, default=str)
            
        self.logger.info(f"Session report saved to {filename}")
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of current session"""
        if not self.current_session:
            return {}
            
        return {
            'target': f"{self.current_session.target_host}:{self.current_session.target_port}",
            'duration': (self.current_session.end_time or time.time()) - self.current_session.start_time,
            'total_tests': self.current_session.total_tests,
            'success_rate': self.current_session.successful_tests / max(1, self.current_session.total_tests),
            'interesting_findings': len(self.current_session.interesting_results),
            'unique_responses': len(self.seen_responses),
            'function_codes_tested': len(self.function_code_coverage)
        }
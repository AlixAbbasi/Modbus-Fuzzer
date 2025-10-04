#!/usr/bin/env python3
"""
Configuration Management for Modbus Fuzzer
Handles loading and validation of configuration from YAML files
"""

import yaml
import os
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

@dataclass
class TargetConfig:
    """Target device configuration"""
    host: str = "127.0.0.1"
    port: int = 502
    timeout: float = 0.5
    max_retries: int = 3
    retry_delay: float = 0.1

@dataclass
class FuzzingConfig:
    """Fuzzing strategy configuration"""
    strategies: List[str] = field(default_factory=lambda: ["grammar_based", "boundary_values"])
    function_codes: List[int] = field(default_factory=list)
    max_tests_per_function: int = 1000
    delay_between_tests: float = 0.01
    enable_response_analysis: bool = True
    enable_variable_data_patterns: bool = True

@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    console_output: bool = True
    file_output: bool = True
    log_file: str = "fuzzer.log"
    json_format: bool = False

@dataclass
class OutputConfig:
    """Output and reporting configuration"""
    save_session_report: bool = True
    report_file: str = "fuzzing_session_{timestamp}.json"
    save_interesting_only: bool = False
    max_report_size_mb: int = 100

@dataclass
class ConnectionPoolConfig:
    """Connection pool configuration"""
    max_connections: int = 5

@dataclass
class PerformanceConfig:
    """Performance optimization configuration"""
    parallel_connections: int = 1
    batch_size: int = 100

@dataclass
class SafetyConfig:
    """Safety and protection configuration"""
    max_session_duration: int = 3600
    max_total_tests: int = 100000
    enable_target_health_check: bool = True
    health_check_interval: int = 300

@dataclass
class AdvancedConfig:
    """Advanced configuration options"""
    connection_pool: ConnectionPoolConfig = field(default_factory=ConnectionPoolConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)

@dataclass
class ModbusFuzzerConfig:
    """Complete Modbus fuzzer configuration"""
    target: TargetConfig = field(default_factory=TargetConfig)
    fuzzing: FuzzingConfig = field(default_factory=FuzzingConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    advanced: AdvancedConfig = field(default_factory=AdvancedConfig)

class ConfigManager:
    """Manages configuration loading, validation, and access"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_file: Path to YAML configuration file
        """
        self.config_file = config_file or "config.yaml"
        self.config: Optional[ModbusFuzzerConfig] = None
        self.logger = logging.getLogger(__name__)
        
    def load_config(self) -> ModbusFuzzerConfig:
        """
        Load configuration from file or create default
        
        Returns:
            ModbusFuzzerConfig instance
        """
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = yaml.safe_load(f)
                    
                self.config = self._create_config_from_dict(config_data)
                self.logger.info(f"Loaded configuration from {self.config_file}")
                
            except Exception as e:
                self.logger.error(f"Failed to load config from {self.config_file}: {e}")
                self.logger.info("Using default configuration")
                self.config = ModbusFuzzerConfig()
        else:
            self.logger.warning(f"Config file {self.config_file} not found, using defaults")
            self.config = ModbusFuzzerConfig()
            
        # Validate configuration
        self._validate_config()
        return self.config
    
    def _create_config_from_dict(self, config_data: Dict[str, Any]) -> ModbusFuzzerConfig:
        """Create configuration objects from dictionary"""
        
        # Target configuration
        target_data = config_data.get('target', {})
        target_config = TargetConfig(
            host=target_data.get('host', "127.0.0.1"),
            port=target_data.get('port', 502),
            timeout=target_data.get('timeout', 0.5),
            max_retries=target_data.get('max_retries', 3),
            retry_delay=target_data.get('retry_delay', 0.1)
        )
        
        # Fuzzing configuration
        fuzzing_data = config_data.get('fuzzing', {})
        fuzzing_config = FuzzingConfig(
            strategies=fuzzing_data.get('strategies', ["grammar_based", "boundary_values"]),
            function_codes=fuzzing_data.get('function_codes', []),
            max_tests_per_function=fuzzing_data.get('max_tests_per_function', 1000),
            delay_between_tests=fuzzing_data.get('delay_between_tests', 0.01),
            enable_response_analysis=fuzzing_data.get('enable_response_analysis', True),
            enable_variable_data_patterns=fuzzing_data.get('enable_variable_data_patterns', True)
        )
        
        # Logging configuration
        logging_data = config_data.get('logging', {})
        logging_config = LoggingConfig(
            level=logging_data.get('level', "INFO"),
            console_output=logging_data.get('console_output', True),
            file_output=logging_data.get('file_output', True),
            log_file=logging_data.get('log_file', "fuzzer.log"),
            json_format=logging_data.get('json_format', False)
        )
        
        # Output configuration
        output_data = config_data.get('output', {})
        output_config = OutputConfig(
            save_session_report=output_data.get('save_session_report', True),
            report_file=output_data.get('report_file', "fuzzing_session_{timestamp}.json"),
            save_interesting_only=output_data.get('save_interesting_only', False),
            max_report_size_mb=output_data.get('max_report_size_mb', 100)
        )
        
        # Advanced configuration
        advanced_data = config_data.get('advanced', {})
        
        connection_pool_data = advanced_data.get('connection_pool', {})
        connection_pool_config = ConnectionPoolConfig(
            max_connections=connection_pool_data.get('max_connections', 5)
        )
        
        performance_data = advanced_data.get('performance', {})
        performance_config = PerformanceConfig(
            parallel_connections=performance_data.get('parallel_connections', 1),
            batch_size=performance_data.get('batch_size', 100)
        )
        
        safety_data = advanced_data.get('safety', {})
        safety_config = SafetyConfig(
            max_session_duration=safety_data.get('max_session_duration', 3600),
            max_total_tests=safety_data.get('max_total_tests', 100000),
            enable_target_health_check=safety_data.get('enable_target_health_check', True),
            health_check_interval=safety_data.get('health_check_interval', 300)
        )
        
        advanced_config = AdvancedConfig(
            connection_pool=connection_pool_config,
            performance=performance_config,
            safety=safety_config
        )
        
        return ModbusFuzzerConfig(
            target=target_config,
            fuzzing=fuzzing_config,
            logging=logging_config,
            output=output_config,
            advanced=advanced_config
        )
    
    def _validate_config(self) -> None:
        """Validate configuration values"""
        if not self.config:
            return
            
        # Validate target configuration
        if not self.config.target.host:
            raise ValueError("Target host cannot be empty")
            
        if not (1 <= self.config.target.port <= 65535):
            raise ValueError(f"Invalid port: {self.config.target.port}")
            
        if self.config.target.timeout <= 0:
            raise ValueError(f"Timeout must be positive: {self.config.target.timeout}")
            
        # Validate fuzzing configuration
        valid_strategies = ["grammar_based", "boundary_values", "mutation", "stress_test", "state_based"]
        for strategy in self.config.fuzzing.strategies:
            if strategy not in valid_strategies:
                raise ValueError(f"Invalid strategy: {strategy}")
                
        if self.config.fuzzing.max_tests_per_function <= 0:
            raise ValueError("max_tests_per_function must be positive")
            
        if self.config.fuzzing.delay_between_tests < 0:
            raise ValueError("delay_between_tests cannot be negative")
            
        # Validate logging configuration
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        if self.config.logging.level not in valid_log_levels:
            raise ValueError(f"Invalid log level: {self.config.logging.level}")
            
        # Validate safety limits
        if self.config.advanced.safety.max_session_duration <= 0:
            raise ValueError("max_session_duration must be positive")
            
        if self.config.advanced.safety.max_total_tests <= 0:
            raise ValueError("max_total_tests must be positive")
            
        self.logger.debug("Configuration validation passed")
    
    def save_config(self, filename: Optional[str] = None) -> None:
        """
        Save current configuration to file
        
        Args:
            filename: Output filename (default: current config file)
        """
        if not self.config:
            raise RuntimeError("No configuration loaded")
            
        output_file = filename or self.config_file
        
        # Convert config to dictionary
        config_dict = {
            'target': {
                'host': self.config.target.host,
                'port': self.config.target.port,
                'timeout': self.config.target.timeout,
                'max_retries': self.config.target.max_retries,
                'retry_delay': self.config.target.retry_delay
            },
            'fuzzing': {
                'strategies': self.config.fuzzing.strategies,
                'function_codes': self.config.fuzzing.function_codes,
                'max_tests_per_function': self.config.fuzzing.max_tests_per_function,
                'delay_between_tests': self.config.fuzzing.delay_between_tests,
                'enable_response_analysis': self.config.fuzzing.enable_response_analysis,
                'enable_variable_data_patterns': self.config.fuzzing.enable_variable_data_patterns
            },
            'logging': {
                'level': self.config.logging.level,
                'console_output': self.config.logging.console_output,
                'file_output': self.config.logging.file_output,
                'log_file': self.config.logging.log_file,
                'json_format': self.config.logging.json_format
            },
            'output': {
                'save_session_report': self.config.output.save_session_report,
                'report_file': self.config.output.report_file,
                'save_interesting_only': self.config.output.save_interesting_only,
                'max_report_size_mb': self.config.output.max_report_size_mb
            },
            'advanced': {
                'connection_pool': {
                    'max_connections': self.config.advanced.connection_pool.max_connections
                },
                'performance': {
                    'parallel_connections': self.config.advanced.performance.parallel_connections,
                    'batch_size': self.config.advanced.performance.batch_size
                },
                'safety': {
                    'max_session_duration': self.config.advanced.safety.max_session_duration,
                    'max_total_tests': self.config.advanced.safety.max_total_tests,
                    'enable_target_health_check': self.config.advanced.safety.enable_target_health_check,
                    'health_check_interval': self.config.advanced.safety.health_check_interval
                }
            }
        }
        
        with open(output_file, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
            
        self.logger.info(f"Configuration saved to {output_file}")
    
    def get_config(self) -> ModbusFuzzerConfig:
        """Get current configuration"""
        if not self.config:
            self.load_config()
        return self.config
    
    def update_target(self, host: str, port: int = 502) -> None:
        """Update target configuration"""
        if not self.config:
            self.load_config()
        self.config.target.host = host
        self.config.target.port = port
        self.logger.info(f"Updated target to {host}:{port}")
    
    def add_strategy(self, strategy: str) -> None:
        """Add a fuzzing strategy"""
        if not self.config:
            self.load_config()
        if strategy not in self.config.fuzzing.strategies:
            self.config.fuzzing.strategies.append(strategy)
            self.logger.info(f"Added fuzzing strategy: {strategy}")
    
    def set_function_codes(self, function_codes: List[int]) -> None:
        """Set specific function codes to test"""
        if not self.config:
            self.load_config()
        self.config.fuzzing.function_codes = function_codes
        self.logger.info(f"Set function codes: {function_codes}")

def setup_logging(config: LoggingConfig) -> None:
    """Setup logging based on configuration"""
    
    # Convert string level to logging constant
    level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR
    }
    
    log_level = level_map.get(config.level, logging.INFO)
    
    # Create formatters
    if config.json_format:
        import json
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_entry = {
                    'timestamp': self.formatTime(record),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage()
                }
                if record.exc_info:
                    log_entry['exception'] = self.formatException(record.exc_info)
                return json.dumps(log_entry)
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter('[%(asctime)s][%(levelname)s][%(name)s] %(message)s')
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler
    if config.console_output:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # File handler
    if config.file_output:
        file_handler = logging.FileHandler(config.log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
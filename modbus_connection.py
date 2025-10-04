#!/usr/bin/env python3
"""
Modbus Connection Management
Robust connection handling with retry logic and error recovery
"""

import socket
import time
import logging
from typing import Optional, Tuple
from contextlib import contextmanager

class ModbusConnection:
    """Manages Modbus TCP connections with automatic retry and recovery"""
    
    def __init__(self, 
                 host: str, 
                 port: int = 502, 
                 timeout: float = 0.5,
                 max_retries: int = 3,
                 retry_delay: float = 0.1):
        """
        Initialize Modbus connection manager
        
        Args:
            host: Target IP address
            port: Target port (default 502)
            timeout: Socket timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.socket: Optional[socket.socket] = None
        self.is_connected = False
        self.connection_attempts = 0
        self.successful_sends = 0
        self.failed_sends = 0
        self.logger = logging.getLogger(__name__)
        
    def connect(self) -> bool:
        """
        Establish connection to Modbus device
        
        Returns:
            True if connection successful, False otherwise
        """
        for attempt in range(self.max_retries + 1):
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(self.timeout)
                self.socket.connect((self.host, self.port))
                self.is_connected = True
                self.connection_attempts += 1
                self.logger.info(f"Connected to {self.host}:{self.port}")
                return True
                
            except socket.timeout:
                self.logger.warning(f"Connection timeout to {self.host}:{self.port} (attempt {attempt + 1})")
            except socket.error as e:
                self.logger.warning(f"Connection failed to {self.host}:{self.port}: {e} (attempt {attempt + 1})")
            except Exception as e:
                self.logger.error(f"Unexpected error connecting to {self.host}:{self.port}: {e}")
                
            # Clean up failed socket
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
                
            # Wait before retry (except on last attempt)
            if attempt < self.max_retries:
                time.sleep(self.retry_delay)
                
        self.is_connected = False
        self.logger.error(f"Failed to connect to {self.host}:{self.port} after {self.max_retries + 1} attempts")
        return False
    
    def disconnect(self) -> None:
        """Close the connection"""
        if self.socket:
            try:
                self.socket.close()
                self.logger.debug(f"Disconnected from {self.host}:{self.port}")
            except Exception as e:
                self.logger.warning(f"Error during disconnect: {e}")
            finally:
                self.socket = None
                self.is_connected = False
    
    def send_and_receive(self, packet: bytes, expect_response: bool = True) -> Tuple[bool, Optional[bytes], float]:
        """
        Send packet and optionally receive response with automatic retry
        
        Args:
            packet: Modbus packet to send
            expect_response: Whether to wait for a response
            
        Returns:
            Tuple of (success, response_data, response_time)
        """
        if not self.is_connected:
            if not self.connect():
                return False, None, 0.0
                
        for attempt in range(self.max_retries + 1):
            try:
                # Send packet
                start_time = time.time()
                bytes_sent = self.socket.send(packet)
                
                if bytes_sent != len(packet):
                    self.logger.warning(f"Incomplete send: {bytes_sent}/{len(packet)} bytes")
                    
                self.successful_sends += 1
                self.logger.debug(f"Sent {len(packet)} bytes to {self.host}:{self.port}")
                
                # Receive response if expected
                if expect_response:
                    try:
                        response = self.socket.recv(1024)
                        response_time = time.time() - start_time
                        
                        if response:
                            self.logger.debug(f"Received {len(response)} bytes from {self.host}:{self.port}")
                            return True, response, response_time
                        else:
                            self.logger.warning("Received empty response")
                            return True, b'', response_time
                            
                    except socket.timeout:
                        response_time = time.time() - start_time
                        self.logger.debug(f"Receive timeout after {response_time:.3f}s")
                        return True, None, response_time
                        
                else:
                    # No response expected
                    return True, None, 0.0
                    
            except socket.error as e:
                self.failed_sends += 1
                self.logger.warning(f"Send/receive failed: {e} (attempt {attempt + 1})")
                self.is_connected = False
                
                # Try to reconnect for next attempt
                if attempt < self.max_retries:
                    self.disconnect()
                    time.sleep(self.retry_delay)
                    if not self.connect():
                        continue
                        
            except Exception as e:
                self.failed_sends += 1
                self.logger.error(f"Unexpected error in send/receive: {e}")
                self.is_connected = False
                break
                
        # All attempts failed
        self.logger.error(f"Failed to send packet after {self.max_retries + 1} attempts")
        return False, None, 0.0
    
    def send_only(self, packet: bytes) -> bool:
        """
        Send packet without expecting response
        
        Args:
            packet: Modbus packet to send
            
        Returns:
            True if send successful, False otherwise
        """
        success, _, _ = self.send_and_receive(packet, expect_response=False)
        return success
    
    def is_alive(self) -> bool:
        """
        Check if connection is still alive
        
        Returns:
            True if connection is alive, False otherwise
        """
        if not self.is_connected or not self.socket:
            return False
            
        try:
            # Send a simple diagnostic packet to test connection
            # Function 8, Sub-function 0 (Return Query Data)
            test_packet = b'\x00\x00\x00\x00\x00\x06\x00\x08\x00\x00\x00\x00'
            self.socket.settimeout(0.1)  # Short timeout for alive check
            self.socket.send(test_packet)
            
            # Try to receive response (don't care about content)
            try:
                self.socket.recv(1024)
            except socket.timeout:
                pass  # Timeout is OK for alive check
                
            return True
            
        except socket.error:
            self.is_connected = False
            return False
        except Exception as e:
            self.logger.warning(f"Unexpected error in alive check: {e}")
            self.is_connected = False
            return False
        finally:
            # Restore original timeout
            if self.socket:
                try:
                    self.socket.settimeout(self.timeout)
                except:
                    pass
    
    def get_stats(self) -> dict:
        """Get connection statistics"""
        return {
            'host': self.host,
            'port': self.port,
            'is_connected': self.is_connected,
            'connection_attempts': self.connection_attempts,
            'successful_sends': self.successful_sends,
            'failed_sends': self.failed_sends,
            'success_rate': self.successful_sends / max(1, self.successful_sends + self.failed_sends)
        }
    
    @contextmanager
    def connection_context(self):
        """Context manager for automatic connection handling"""
        try:
            if not self.is_connected:
                self.connect()
            yield self
        finally:
            self.disconnect()
    
    def __enter__(self):
        """Context manager entry"""
        if not self.is_connected:
            self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
    
    def __del__(self):
        """Cleanup on object destruction"""
        self.disconnect()

class ModbusConnectionPool:
    """Manage multiple Modbus connections for parallel fuzzing"""
    
    def __init__(self, max_connections: int = 5):
        """
        Initialize connection pool
        
        Args:
            max_connections: Maximum number of concurrent connections
        """
        self.max_connections = max_connections
        self.connections = {}
        self.logger = logging.getLogger(__name__)
    
    def get_connection(self, host: str, port: int = 502, **kwargs) -> ModbusConnection:
        """
        Get or create a connection for the specified host:port
        
        Args:
            host: Target IP address
            port: Target port
            **kwargs: Additional connection parameters
            
        Returns:
            ModbusConnection instance
        """
        key = f"{host}:{port}"
        
        if key not in self.connections:
            if len(self.connections) >= self.max_connections:
                # Remove oldest connection
                oldest_key = next(iter(self.connections))
                self.connections[oldest_key].disconnect()
                del self.connections[oldest_key]
                
            self.connections[key] = ModbusConnection(host, port, **kwargs)
            
        return self.connections[key]
    
    def close_all(self):
        """Close all connections in the pool"""
        for connection in self.connections.values():
            connection.disconnect()
        self.connections.clear()
        self.logger.info("Closed all connections in pool")
    
    def get_pool_stats(self) -> dict:
        """Get statistics for all connections in pool"""
        stats = {}
        for key, connection in self.connections.items():
            stats[key] = connection.get_stats()
        return stats
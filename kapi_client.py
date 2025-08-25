
#!/usr/bin/env python3
"""
Kernel API Client - Python userland interface for the kernel driver
This module provides a high-level interface to communicate with the kernel driver
"""

import os
import sys
import struct
import fcntl
import mmap
import socket
import time
from ctypes import *

# Device path
DEVICE_PATH = "/dev/kernel_api_exporter"

# IOCTL commands (must match kernel driver)
KAPI_IOC_MAGIC = ord('k')
KAPI_GET_MEMORY_INFO = (2 << 30) | (KAPI_IOC_MAGIC << 8) | 1 | (0 << 16)
KAPI_GET_CPU_INFO = (2 << 30) | (KAPI_IOC_MAGIC << 8) | 2 | (0 << 16)
KAPI_GET_PROCESS_INFO = (3 << 30) | (KAPI_IOC_MAGIC << 8) | 3 | (0 << 16)
KAPI_EXECUTE_KERNEL_CMD = (3 << 30) | (KAPI_IOC_MAGIC << 8) | 4 | (0 << 16)
KAPI_GET_NETWORK_STATS = (2 << 30) | (KAPI_IOC_MAGIC << 8) | 5 | (0 << 16)

# Netlink constants
NETLINK_USER = 31

# Data structures (must match kernel structures)
class MemoryInfo(Structure):
    _fields_ = [
        ("total_ram", c_ulong),
        ("free_ram", c_ulong),
        ("used_ram", c_ulong),
        ("buffers", c_ulong),
        ("cached", c_ulong),
        ("swap_total", c_ulong),
        ("swap_free", c_ulong),
    ]

class CPUInfo(Structure):
    _fields_ = [
        ("num_cpus", c_uint),
        ("cpu_freq", c_ulong),
        ("cpu_model", c_char * 64),
        ("uptime", c_ulong),
        ("idle_time", c_ulong),
    ]

class ProcessInfo(Structure):
    _fields_ = [
        ("pid", c_int),
        ("comm", c_char * 16),
        ("memory_usage", c_ulong),
        ("cpu_usage", c_uint),
        ("num_threads", c_int),
    ]

class KernelCmd(Structure):
    _fields_ = [
        ("command", c_char * 256),
        ("result", c_char * 1024),
        ("status", c_int),
    ]

class NetworkStats(Structure):
    _fields_ = [
        ("rx_packets", c_ulong),
        ("tx_packets", c_ulong),
        ("rx_bytes", c_ulong),
        ("tx_bytes", c_ulong),
        ("rx_errors", c_ulong),
        ("tx_errors", c_ulong),
    ]

class KernelAPIClient:
    """Main client class for communicating with the kernel driver"""
    
    def __init__(self):
        self.device_fd = None
        self.netlink_socket = None
        self.shared_memory = None
        
    def connect(self):
        """Connect to the kernel driver"""
        try:
            # Open character device
            self.device_fd = os.open(DEVICE_PATH, os.O_RDWR)
            print(f"Connected to kernel driver at {DEVICE_PATH}")
            
            # Create netlink socket
            self.netlink_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_USER)
            self.netlink_socket.bind((os.getpid(), 0))
            print("Netlink socket created")
            
            # Memory map the device
            self.shared_memory = mmap.mmap(self.device_fd, 4096, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
            print("Memory mapped device buffer")
            
            return True
            
        except Exception as e:
            print(f"Failed to connect to kernel driver: {e}")
            self.disconnect()
            return False
    
    def disconnect(self):
        """Disconnect from the kernel driver"""
        if self.shared_memory:
            self.shared_memory.close()
            self.shared_memory = None
            
        if self.netlink_socket:
            self.netlink_socket.close()
            self.netlink_socket = None
            
        if self.device_fd:
            os.close(self.device_fd)
            self.device_fd = None
            
        print("Disconnected from kernel driver")
    
    def get_memory_info(self):
        """Get system memory information"""
        if not self.device_fd:
            raise RuntimeError("Not connected to kernel driver")
        
        mem_info = MemoryInfo()
        try:
            fcntl.ioctl(self.device_fd, KAPI_GET_MEMORY_INFO, mem_info)
            return {
                'total_ram': mem_info.total_ram,
                'free_ram': mem_info.free_ram,
                'used_ram': mem_info.used_ram,
                'buffers': mem_info.buffers,
                'cached': mem_info.cached,
                'swap_total': mem_info.swap_total,
                'swap_free': mem_info.swap_free,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get memory info: {e}")
    
    def get_cpu_info(self):
        """Get CPU information"""
        if not self.device_fd:
            raise RuntimeError("Not connected to kernel driver")
        
        cpu_info = CPUInfo()
        try:
            fcntl.ioctl(self.device_fd, KAPI_GET_CPU_INFO, cpu_info)
            return {
                'num_cpus': cpu_info.num_cpus,
                'cpu_freq': cpu_info.cpu_freq,
                'cpu_model': cpu_info.cpu_model.decode('utf-8'),
                'uptime': cpu_info.uptime,
                'idle_time': cpu_info.idle_time,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get CPU info: {e}")
    
    def get_process_info(self, pid):
        """Get information about a specific process"""
        if not self.device_fd:
            raise RuntimeError("Not connected to kernel driver")
        
        proc_info = ProcessInfo()
        proc_info.pid = pid
        
        try:
            fcntl.ioctl(self.device_fd, KAPI_GET_PROCESS_INFO, proc_info)
            if proc_info.pid == -1:
                return None
                
            return {
                'pid': proc_info.pid,
                'comm': proc_info.comm.decode('utf-8'),
                'memory_usage': proc_info.memory_usage,
                'cpu_usage': proc_info.cpu_usage,
                'num_threads': proc_info.num_threads,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get process info: {e}")
    
    def execute_kernel_command(self, command):
        """Execute a command in kernel space"""
        if not self.device_fd:
            raise RuntimeError("Not connected to kernel driver")
        
        kernel_cmd = KernelCmd()
        kernel_cmd.command = command.encode('utf-8')
        
        try:
            fcntl.ioctl(self.device_fd, KAPI_EXECUTE_KERNEL_CMD, kernel_cmd)
            return {
                'command': kernel_cmd.command.decode('utf-8'),
                'result': kernel_cmd.result.decode('utf-8'),
                'status': kernel_cmd.status,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to execute kernel command: {e}")
    
    def get_network_stats(self):
        """Get network statistics"""
        if not self.device_fd:
            raise RuntimeError("Not connected to kernel driver")
        
        net_stats = NetworkStats()
        try:
            fcntl.ioctl(self.device_fd, KAPI_GET_NETWORK_STATS, net_stats)
            return {
                'rx_packets': net_stats.rx_packets,
                'tx_packets': net_stats.tx_packets,
                'rx_bytes': net_stats.rx_bytes,
                'tx_bytes': net_stats.tx_bytes,
                'rx_errors': net_stats.rx_errors,
                'tx_errors': net_stats.tx_errors,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get network stats: {e}")
    
    def send_netlink_message(self, message):
        """Send a message via netlink"""
        if not self.netlink_socket:
            raise RuntimeError("Netlink socket not available")
        
        try:
            self.netlink_socket.send(message.encode('utf-8'))
            response = self.netlink_socket.recv(1024)
            return response.decode('utf-8')
        except Exception as e:
            raise RuntimeError(f"Netlink communication failed: {e}")
    
    def write_shared_memory(self, data, offset=0):
        """Write data to shared memory"""
        if not self.shared_memory:
            raise RuntimeError("Shared memory not available")
        
        self.shared_memory.seek(offset)
        self.shared_memory.write(data.encode('utf-8') if isinstance(data, str) else data)
        self.shared_memory.flush()
    
    def read_shared_memory(self, size=None, offset=0):
        """Read data from shared memory"""
        if not self.shared_memory:
            raise RuntimeError("Shared memory not available")
        
        self.shared_memory.seek(offset)
        if size is None:
            data = self.shared_memory.read()
        else:
            data = self.shared_memory.read(size)
        
        return data.rstrip(b'\x00').decode('utf-8')

def format_bytes(bytes_value):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def main():
    """Main function demonstrating the API usage"""
    client = KernelAPIClient()
    
    print("=== Kernel API Client Demo ===")
    
    # Connect to kernel driver
    if not client.connect():
        print("Failed to connect to kernel driver")
        return 1
    
    try:
        # Test memory information
        print("\n--- Memory Information ---")
        mem_info = client.get_memory_info()
        print(f"Total RAM: {format_bytes(mem_info['total_ram'])}")
        print(f"Free RAM: {format_bytes(mem_info['free_ram'])}")
        print(f"Used RAM: {format_bytes(mem_info['used_ram'])}")
        print(f"Buffers: {format_bytes(mem_info['buffers'])}")
        print(f"Total Swap: {format_bytes(mem_info['swap_total'])}")
        print(f"Free Swap: {format_bytes(mem_info['swap_free'])}")
        
        # Test CPU information
        print("\n--- CPU Information ---")
        cpu_info = client.get_cpu_info()
        print(f"Number of CPUs: {cpu_info['num_cpus']}")
        print(f"CPU Model: {cpu_info['cpu_model']}")
        print(f"Uptime: {cpu_info['uptime']} seconds")
        
        # Test process information
        print("\n--- Process Information ---")
        current_pid = os.getpid()
        proc_info = client.get_process_info(current_pid)
        if proc_info:
            print(f"PID: {proc_info['pid']}")
            print(f"Command: {proc_info['comm']}")
            print(f"Memory Usage: {format_bytes(proc_info['memory_usage'])}")
            print(f"Number of Threads: {proc_info['num_threads']}")
        else:
            print(f"Process {current_pid} not found")
        
        # Test kernel commands
        print("\n--- Kernel Commands ---")
        commands = ["get_kernel_version", "get_uptime", "invalid_command"]
        for cmd in commands:
            result = client.execute_kernel_command(cmd)
            print(f"Command: {result['command']}")
            print(f"Result: {result['result']}")
            print(f"Status: {result['status']}")
            print()
        
        # Test network statistics
        print("\n--- Network Statistics ---")
        net_stats = client.get_network_stats()
        print(f"RX Packets: {net_stats['rx_packets']}")
        print(f"TX Packets: {net_stats['tx_packets']}")
        print(f"RX Bytes: {format_bytes(net_stats['rx_bytes'])}")
        print(f"TX Bytes: {format_bytes(net_stats['tx_bytes'])}")
        
        # Test shared memory
        print("\n--- Shared Memory Test ---")
        test_data = "Hello from userland!"
        client.write_shared_memory(test_data)
        read_data = client.read_shared_memory()
        print(f"Written: {test_data}")
        print(f"Read: {read_data}")
        
        # Test netlink communication
        print("\n--- Netlink Communication Test ---")
        try:
            response = client.send_netlink_message("Hello kernel!")
            print(f"Netlink response: {response}")
        except Exception as e:
            print(f"Netlink test failed: {e}")
        
    except Exception as e:
        print(f"Error during API testing: {e}")
        return 1
    
    finally:
        client.disconnect()
    
    print("\n=== Demo completed successfully ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())

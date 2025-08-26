#!/usr/bin/env python3
"""
Kernel API Client v2.0 - Advanced Python userland interface for the kernel driver
This module provides a comprehensive interface to communicate with the enhanced kernel driver
"""

import os
import sys
import struct
import fcntl
import mmap
import socket
import time
import json
from ctypes import *
from datetime import datetime

# Device path
DEVICE_PATH = "/dev/kernel_api_exporter"

# IOCTL commands (must match kernel driver)
KAPI_IOC_MAGIC = ord('k')

def _IOC(direction, magic, number, size):
    return (direction << 30) | (magic << 8) | number | (int(size) << 16)

def _IOR(magic, number, struct_type):
    return _IOC(2, magic, number, int(sizeof(struct_type)))

def _IOWR(magic, number, struct_type):
    return _IOC(3, magic, number, int(sizeof(struct_type)))

# Netlink constants
NETLINK_USER = 31

# Enhanced data structures (must match kernel structures)
class MemoryInfo(Structure):
    _fields_ = [
        ("total_ram", c_ulong),
        ("free_ram", c_ulong),
        ("used_ram", c_ulong),
        ("buffers", c_ulong),
        ("cached", c_ulong),
        ("swap_total", c_ulong),
        ("swap_free", c_ulong),
        ("slab", c_ulong),
        ("page_tables", c_ulong),
        ("vmalloc_used", c_ulong),
        ("committed_as", c_ulong),
        ("dirty", c_ulong),
        ("writeback", c_ulong),
        ("anon_pages", c_ulong),
        ("mapped", c_ulong),
        ("shmem", c_ulong),
    ]

class CPUInfo(Structure):
    _fields_ = [
        ("num_cpus", c_uint),
        ("num_online_cpus", c_uint),
        ("cpu_freq", c_ulong),
        ("cpu_model", c_char * 64),
        ("uptime", c_ulong),
        ("idle_time", c_ulong),
        ("user_time", c_ulong),
        ("system_time", c_ulong),
        ("iowait_time", c_ulong),
        ("irq_time", c_ulong),
        ("softirq_time", c_ulong),
        ("guest_time", c_ulong),
        ("cache_size", c_uint),
        ("cache_alignment", c_uint),
        ("vendor_id", c_char * 16),
        ("cpu_family", c_char * 16),
    ]

class ProcessInfo(Structure):
    _fields_ = [
        ("pid", c_int),
        ("comm", c_char * 16),
        ("memory_usage", c_ulong),
        ("cpu_usage", c_uint),
        ("num_threads", c_int),
        ("ppid", c_int),
        ("pgrp", c_int),
        ("session", c_int),
        ("tty_nr", c_int),
        ("start_time", c_ulong),
        ("vsize", c_ulong),
        ("rss", c_long),
        ("rsslim", c_ulong),
        ("priority", c_ulong),
        ("nice", c_long),
        ("num_threads_full", c_ulong),
        ("state", c_char),
        ("flags", c_uint),
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
        ("rx_dropped", c_ulong),
        ("tx_dropped", c_ulong),
        ("multicast", c_ulong),
        ("collisions", c_ulong),
        ("rx_length_errors", c_ulong),
        ("rx_over_errors", c_ulong),
        ("rx_crc_errors", c_ulong),
        ("rx_frame_errors", c_ulong),
        ("rx_fifo_errors", c_ulong),
        ("rx_missed_errors", c_ulong),
        ("tx_aborted_errors", c_ulong),
        ("tx_carrier_errors", c_ulong),
        ("tx_fifo_errors", c_ulong),
        ("tx_heartbeat_errors", c_ulong),
        ("tx_window_errors", c_ulong),
    ]

class FilesystemInfo(Structure):
    _fields_ = [
        ("fs_type", c_char * 32),
        ("total_blocks", c_ulong),
        ("free_blocks", c_ulong),
        ("available_blocks", c_ulong),
        ("total_inodes", c_ulong),
        ("free_inodes", c_ulong),
        ("block_size", c_ulong),
        ("max_filename_len", c_ulong),
        ("mount_point", c_char * 256),
        ("device_name", c_char * 64),
        ("flags", c_ulong),
    ]

class LoadAvgInfo(Structure):
    _fields_ = [
        ("load1", c_ulong),
        ("load5", c_ulong),
        ("load15", c_ulong),
        ("running_tasks", c_ulong),
        ("total_tasks", c_ulong),
        ("last_pid", c_ulong),
    ]

class KernelConfig(Structure):
    _fields_ = [
        ("version", c_char * 64),
        ("compile_time", c_char * 64),
        ("compile_by", c_char * 64),
        ("compile_host", c_char * 64),
        ("compiler", c_char * 64),
        ("build_date", c_char * 64),
        ("hz", c_ulong),
        ("page_size", c_ulong),
        ("phys_addr_bits", c_ulong),
        ("virt_addr_bits", c_ulong),
        ("arch", c_char * 32),
    ]

# Dangerous control structures
class ProcessControl(Structure):
    _fields_ = [
        ("pid", c_int),
        ("signal", c_int),
        ("status", c_int),
        ("message", c_char * 256),
    ]

class ModuleControl(Structure):
    _fields_ = [
        ("path", c_char * 256),
        ("name", c_char * 64),
        ("params", c_char * 256),
        ("status", c_int),
        ("message", c_char * 256),
    ]

class NetControl(Structure):
    _fields_ = [
        ("interface", c_char * 16),
        ("up", c_int),
        ("status", c_int),
        ("message", c_char * 256),
    ]

class FSControl(Structure):
    _fields_ = [
        ("device", c_char * 128),
        ("path", c_char * 256),
        ("type", c_char * 32),
        ("options", c_char * 256),
        ("status", c_int),
        ("message", c_char * 256),
    ]

class LogInjection(Structure):
    _fields_ = [
        ("level", c_char * 16),
        ("message", c_char * 512),
        ("status", c_int),
    ]

class CPUControl(Structure):
    _fields_ = [
        ("pid", c_int),
        ("mask", c_ulong),
        ("status", c_int),
        ("message", c_char * 256),
    ]

def _IOW(magic, number, struct_type):
    return _IOC(1, magic, number, int(sizeof(struct_type)))

def _IO(magic, number):
    return _IOC(0, magic, number, 0)

# IOCTL command definitions
KAPI_GET_MEMORY_INFO = _IOR(KAPI_IOC_MAGIC, 1, MemoryInfo)
KAPI_GET_CPU_INFO = _IOR(KAPI_IOC_MAGIC, 2, CPUInfo)
KAPI_GET_PROCESS_INFO = _IOWR(KAPI_IOC_MAGIC, 3, ProcessInfo)
KAPI_EXECUTE_KERNEL_CMD = _IOWR(KAPI_IOC_MAGIC, 4, KernelCmd)
KAPI_GET_NETWORK_STATS = _IOR(KAPI_IOC_MAGIC, 5, NetworkStats)
KAPI_GET_FILE_SYSTEM_INFO = _IOR(KAPI_IOC_MAGIC, 6, FilesystemInfo)
KAPI_GET_LOADAVG = _IOR(KAPI_IOC_MAGIC, 9, LoadAvgInfo)
KAPI_GET_KERNEL_CONFIG = _IOR(KAPI_IOC_MAGIC, 10, KernelConfig)

# Dangerous control commands
KAPI_KILL_PROCESS = _IOW(KAPI_IOC_MAGIC, 15, ProcessControl)
KAPI_SUSPEND_PROCESS = _IOW(KAPI_IOC_MAGIC, 16, ProcessControl)
KAPI_RESUME_PROCESS = _IOW(KAPI_IOC_MAGIC, 17, ProcessControl)
KAPI_LOAD_MODULE = _IOW(KAPI_IOC_MAGIC, 18, ModuleControl)
KAPI_UNLOAD_MODULE = _IOW(KAPI_IOC_MAGIC, 19, ModuleControl)
KAPI_TOGGLE_INTERFACE = _IOW(KAPI_IOC_MAGIC, 20, NetControl)
KAPI_MOUNT_FS = _IOW(KAPI_IOC_MAGIC, 21, FSControl)
KAPI_UMOUNT_FS = _IOW(KAPI_IOC_MAGIC, 22, FSControl)
KAPI_INJECT_LOG = _IOW(KAPI_IOC_MAGIC, 23, LogInjection)
KAPI_FORCE_PAGE_RECLAIM = _IO(KAPI_IOC_MAGIC, 24)
KAPI_SET_CPU_AFFINITY = _IOW(KAPI_IOC_MAGIC, 25, CPUControl)
KAPI_PANIC_KERNEL = _IO(KAPI_IOC_MAGIC, 26)

class KernelAPIClient:
    """Enhanced client class for communicating with the kernel driver"""

    def __init__(self):
        self.device_fd = None
        self.netlink_socket = None
        self.shared_memory = None
        self.connected = False

    def connect(self):
        """Connect to the kernel driver"""
        try:
            # Check if device exists
            if not os.path.exists(DEVICE_PATH):
                print(f"Device {DEVICE_PATH} not found. Make sure the kernel module is loaded.")
                return False

            # Open character device
            self.device_fd = os.open(DEVICE_PATH, os.O_RDWR)
            print(f"✓ Connected to kernel driver at {DEVICE_PATH}")

            # Create netlink socket
            try:
                self.netlink_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_USER)
                self.netlink_socket.bind((os.getpid(), 0))
                print("✓ Netlink socket created")
            except Exception as e:
                print(f"⚠ Netlink socket creation failed: {e}")
                self.netlink_socket = None

            # Memory map the device (16KB buffer)
            try:
                # Try to memory map with proper flags
                self.shared_memory = mmap.mmap(
                    self.device_fd, 
                    16384,  # 4 pages * 4KB = 16KB
                    mmap.MAP_SHARED, 
                    mmap.PROT_READ | mmap.PROT_WRITE
                )
                print("✓ Memory mapped device buffer (16KB)")
            except OSError as e:
                print(f"⚠ Memory mapping failed with OSError: {e}")
                print(f"  Error code: {e.errno}")
                # Try alternative mmap approach
                try:
                    self.shared_memory = mmap.mmap(
                        self.device_fd, 
                        0,  # Map entire file
                        mmap.MAP_SHARED, 
                        mmap.PROT_READ | mmap.PROT_WRITE
                    )
                    print("✓ Memory mapped with alternative method")
                except Exception as e2:
                    print(f"⚠ Alternative memory mapping also failed: {e2}")
                    self.shared_memory = None
            except Exception as e:
                print(f"⚠ Memory mapping failed: {e}")
                self.shared_memory = None

            self.connected = True
            return True

        except Exception as e:
            print(f"✗ Failed to connect to kernel driver: {e}")
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

        self.connected = False
        print("✓ Disconnected from kernel driver")

    def is_connected(self):
        """Check if connected to the kernel driver"""
        return self.connected and self.device_fd is not None

    def get_memory_info(self):
        """Get comprehensive system memory information"""
        if not self.is_connected():
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
                'slab': mem_info.slab,
                'page_tables': mem_info.page_tables,
                'vmalloc_used': mem_info.vmalloc_used,
                'committed_as': mem_info.committed_as,
                'dirty': mem_info.dirty,
                'writeback': mem_info.writeback,
                'anon_pages': mem_info.anon_pages,
                'mapped': mem_info.mapped,
                'shmem': mem_info.shmem,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get memory info: {e}")

    def get_cpu_info(self):
        """Get comprehensive CPU information"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        cpu_info = CPUInfo()
        try:
            fcntl.ioctl(self.device_fd, KAPI_GET_CPU_INFO, cpu_info)
            return {
                'num_cpus': cpu_info.num_cpus,
                'num_online_cpus': cpu_info.num_online_cpus,
                'cpu_freq': cpu_info.cpu_freq,
                'cpu_model': cpu_info.cpu_model.decode('utf-8').strip('\x00'),
                'uptime': cpu_info.uptime,
                'idle_time': cpu_info.idle_time,
                'user_time': cpu_info.user_time,
                'system_time': cpu_info.system_time,
                'iowait_time': cpu_info.iowait_time,
                'irq_time': cpu_info.irq_time,
                'softirq_time': cpu_info.softirq_time,
                'guest_time': cpu_info.guest_time,
                'cache_size': cpu_info.cache_size,
                'cache_alignment': cpu_info.cache_alignment,
                'vendor_id': cpu_info.vendor_id.decode('utf-8').strip('\x00'),
                'cpu_family': cpu_info.cpu_family.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get CPU info: {e}")

    def get_process_info(self, pid):
        """Get comprehensive information about a specific process"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        proc_info = ProcessInfo()
        proc_info.pid = pid

        try:
            fcntl.ioctl(self.device_fd, KAPI_GET_PROCESS_INFO, proc_info)
            if proc_info.pid == -1:
                return None

            # Safe state handling
            try:
                if hasattr(proc_info.state, 'value'):
                    state_val = proc_info.state.value
                else:
                    state_val = proc_info.state

                if isinstance(state_val, bytes):
                    state_char = state_val.decode('utf-8')[0] if len(state_val) > 0 else 'U'
                elif isinstance(state_val, int) and state_val > 0:
                    state_char = chr(state_val)
                else:
                    state_char = 'U'
            except:
                state_char = 'U'

            return {
                'pid': proc_info.pid,
                'comm': proc_info.comm.decode('utf-8').strip('\x00'),
                'memory_usage': proc_info.memory_usage,
                'cpu_usage': proc_info.cpu_usage,
                'num_threads': proc_info.num_threads,
                'ppid': proc_info.ppid,
                'pgrp': proc_info.pgrp,
                'session': proc_info.session,
                'tty_nr': proc_info.tty_nr,
                'start_time': proc_info.start_time,
                'vsize': proc_info.vsize,
                'rss': proc_info.rss,
                'rsslim': proc_info.rsslim,
                'priority': proc_info.priority,
                'nice': proc_info.nice,
                'num_threads_full': proc_info.num_threads_full,
                'state': state_char,
                'flags': proc_info.flags,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get process info: {e}")

    def execute_kernel_command(self, command):
        """Execute a command in kernel space"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        kernel_cmd = KernelCmd()
        kernel_cmd.command = command.encode('utf-8')

        try:
            fcntl.ioctl(self.device_fd, KAPI_EXECUTE_KERNEL_CMD, kernel_cmd)
            return {
                'command': kernel_cmd.command.decode('utf-8').strip('\x00'),
                'result': kernel_cmd.result.decode('utf-8').strip('\x00'),
                'status': kernel_cmd.status,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to execute kernel command: {e}")

    def get_network_stats(self):
        """Get comprehensive network statistics"""
        if not self.is_connected():
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
                'rx_dropped': net_stats.rx_dropped,
                'tx_dropped': net_stats.tx_dropped,
                'multicast': net_stats.multicast,
                'collisions': net_stats.collisions,
                'rx_length_errors': net_stats.rx_length_errors,
                'rx_over_errors': net_stats.rx_over_errors,
                'rx_crc_errors': net_stats.rx_crc_errors,
                'rx_frame_errors': net_stats.rx_frame_errors,
                'rx_fifo_errors': net_stats.rx_fifo_errors,
                'rx_missed_errors': net_stats.rx_missed_errors,
                'tx_aborted_errors': net_stats.tx_aborted_errors,
                'tx_carrier_errors': net_stats.tx_carrier_errors,
                'tx_fifo_errors': net_stats.tx_fifo_errors,
                'tx_heartbeat_errors': net_stats.tx_heartbeat_errors,
                'tx_window_errors': net_stats.tx_window_errors,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get network stats: {e}")

    def get_filesystem_info(self):
        """Get filesystem information"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        fs_info = FilesystemInfo()
        try:
            fcntl.ioctl(self.device_fd, KAPI_GET_FILE_SYSTEM_INFO, fs_info)
            return {
                'fs_type': fs_info.fs_type.decode('utf-8').strip('\x00'),
                'total_blocks': fs_info.total_blocks,
                'free_blocks': fs_info.free_blocks,
                'available_blocks': fs_info.available_blocks,
                'total_inodes': fs_info.total_inodes,
                'free_inodes': fs_info.free_inodes,
                'block_size': fs_info.block_size,
                'max_filename_len': fs_info.max_filename_len,
                'mount_point': fs_info.mount_point.decode('utf-8').strip('\x00'),
                'device_name': fs_info.device_name.decode('utf-8').strip('\x00'),
                'flags': fs_info.flags,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get filesystem info: {e}")

    def get_load_average(self):
        """Get system load average information"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        load_info = LoadAvgInfo()
        try:
            fcntl.ioctl(self.device_fd, KAPI_GET_LOADAVG, load_info)
            return {
                'load1': load_info.load1 / 65536.0,  # Convert from fixed point
                'load5': load_info.load5 / 65536.0,
                'load15': load_info.load15 / 65536.0,
                'running_tasks': load_info.running_tasks,
                'total_tasks': load_info.total_tasks,
                'last_pid': load_info.last_pid,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get load average: {e}")

    def get_kernel_config(self):
        """Get kernel configuration information"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        config = KernelConfig()
        try:
            fcntl.ioctl(self.device_fd, KAPI_GET_KERNEL_CONFIG, config)
            return {
                'version': config.version.decode('utf-8').strip('\x00'),
                'compile_time': config.compile_time.decode('utf-8').strip('\x00'),
                'compile_by': config.compile_by.decode('utf-8').strip('\x00'),
                'compile_host': config.compile_host.decode('utf-8').strip('\x00'),
                'compiler': config.compiler.decode('utf-8').strip('\x00'),
                'build_date': config.build_date.decode('utf-8').strip('\x00'),
                'hz': config.hz,
                'page_size': config.page_size,
                'phys_addr_bits': config.phys_addr_bits,
                'virt_addr_bits': config.virt_addr_bits,
                'arch': config.arch.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to get kernel config: {e}")

    def send_netlink_message(self, message):
        """Send a message via netlink"""
        if not self.netlink_socket:
            raise RuntimeError("Netlink socket not available")

        try:
            # Create proper netlink message header
            msg_data = message.encode('utf-8')
            msg_len = len(msg_data)
            
            # Netlink message header (16 bytes)
            # struct nlmsghdr: len(4) + type(2) + flags(2) + seq(4) + pid(4)
            nlmsg_len = 16 + msg_len
            nlmsg_type = 0  # NLMSG_NOOP
            nlmsg_flags = 0
            nlmsg_seq = 0
            nlmsg_pid = os.getpid()
            
            header = struct.pack('IHHII', nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid)
            full_msg = header + msg_data
            
            self.netlink_socket.send(full_msg)
            
            # Receive response
            response = self.netlink_socket.recv(1024)
            
            # Parse netlink response
            if len(response) >= 16:
                # Skip netlink header (16 bytes) and get message data
                msg_data = response[16:]
                return msg_data.decode('utf-8').rstrip('\x00')
            else:
                return "Invalid response"
                
        except Exception as e:
            raise RuntimeError(f"Netlink communication failed: {e}")

    def write_shared_memory(self, data, offset=0):
        """Write data to shared memory"""
        if not self.shared_memory:
            raise RuntimeError("Shared memory not available")

        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            if offset + len(data) > len(self.shared_memory):
                raise RuntimeError(f"Data too large: {len(data)} bytes at offset {offset}")
            
            # Write data directly to memory map
            self.shared_memory[offset:offset+len(data)] = data
            
            # Ensure data is written to kernel
            self.shared_memory.flush()
            
        except Exception as e:
            raise RuntimeError(f"Failed to write to shared memory: {e}")

    def read_shared_memory(self, size=None, offset=0):
        """Read data from shared memory"""
        if not self.shared_memory:
            raise RuntimeError("Shared memory not available")

        try:
            if size is None:
                size = len(self.shared_memory) - offset
            
            if offset + size > len(self.shared_memory):
                size = len(self.shared_memory) - offset
            
            # Read data directly from memory map
            data = self.shared_memory[offset:offset+size]
            
            # Remove null bytes and decode
            if isinstance(data, bytes):
                return data.rstrip(b'\x00').decode('utf-8', errors='ignore')
            else:
                return str(data).rstrip('\x00')
                
        except Exception as e:
            raise RuntimeError(f"Failed to read from shared memory: {e}")

    def get_all_available_commands(self):
        """Get list of all available kernel commands"""
        commands = [
            "get_kernel_version",
            "get_uptime",
            "get_hostname",
            "get_domainname",
            "get_total_memory",
            "get_free_memory",
            "get_cpu_count",
            "get_page_size",
            "get_hz",
            "get_jiffies"
        ]
        return commands

    def export_system_info(self, filename=None):
        """Export comprehensive system information to JSON"""
        if not filename:
            filename = f"system_info_{int(time.time())}.json"

        system_info = {
            'timestamp': datetime.now().isoformat(),
            'kernel_config': self.get_kernel_config(),
            'memory_info': self.get_memory_info(),
            'cpu_info': self.get_cpu_info(),
            'load_average': self.get_load_average(),
            'network_stats': self.get_network_stats(),
            'filesystem_info': self.get_filesystem_info(),
            'current_process': self.get_process_info(os.getpid()),
        }

        # Add kernel command results
        system_info['kernel_commands'] = {}
        for cmd in self.get_all_available_commands():
            try:
                result = self.execute_kernel_command(cmd)
                system_info['kernel_commands'][cmd] = result
            except Exception as e:
                system_info['kernel_commands'][cmd] = {'error': str(e)}

        with open(filename, 'w') as f:
            json.dump(system_info, f, indent=2)

        return filename

    # 🔥 DANGEROUS CONTROL METHODS 🔥
    # These methods can seriously damage your system!

    def kill_process(self, pid, signal=9):
        """⚠️ DANGEROUS: Kill a process with specified signal"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        ctrl = ProcessControl()
        ctrl.pid = pid
        ctrl.signal = signal

        try:
            fcntl.ioctl(self.device_fd, KAPI_KILL_PROCESS, ctrl)
            return {
                'status': ctrl.status,
                'message': ctrl.message.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to kill process: {e}")

    def suspend_process(self, pid):
        """⚠️ DANGEROUS: Suspend a process (SIGSTOP)"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        ctrl = ProcessControl()
        ctrl.pid = pid

        try:
            fcntl.ioctl(self.device_fd, KAPI_SUSPEND_PROCESS, ctrl)
            return {
                'status': ctrl.status,
                'message': ctrl.message.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to suspend process: {e}")

    def resume_process(self, pid):
        """⚠️ DANGEROUS: Resume a suspended process (SIGCONT)"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        ctrl = ProcessControl()
        ctrl.pid = pid

        try:
            fcntl.ioctl(self.device_fd, KAPI_RESUME_PROCESS, ctrl)
            return {
                'status': ctrl.status,
                'message': ctrl.message.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to resume process: {e}")

    def load_kernel_module(self, path, params=""):
        """⚠️ DANGEROUS: Load a kernel module"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        ctrl = ModuleControl()
        ctrl.path = path.encode('utf-8')
        ctrl.params = params.encode('utf-8')

        try:
            fcntl.ioctl(self.device_fd, KAPI_LOAD_MODULE, ctrl)
            return {
                'status': ctrl.status,
                'message': ctrl.message.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to load module: {e}")

    def unload_kernel_module(self, name):
        """⚠️ DANGEROUS: Unload a kernel module"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        ctrl = ModuleControl()
        ctrl.name = name.encode('utf-8')

        try:
            fcntl.ioctl(self.device_fd, KAPI_UNLOAD_MODULE, ctrl)
            return {
                'status': ctrl.status,
                'message': ctrl.message.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to unload module: {e}")

    def toggle_network_interface(self, interface, up=True):
        """⚠️ DANGEROUS: Bring network interface up/down"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        ctrl = NetControl()
        ctrl.interface = interface.encode('utf-8')
        ctrl.up = 1 if up else 0

        try:
            fcntl.ioctl(self.device_fd, KAPI_TOGGLE_INTERFACE, ctrl)
            return {
                'status': ctrl.status,
                'message': ctrl.message.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to toggle interface: {e}")

    def mount_filesystem(self, device, path, fs_type="ext4", options=""):
        """⚠️ DANGEROUS: Mount a filesystem"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        ctrl = FSControl()
        ctrl.device = device.encode('utf-8')
        ctrl.path = path.encode('utf-8')
        ctrl.type = fs_type.encode('utf-8')
        ctrl.options = options.encode('utf-8')

        try:
            fcntl.ioctl(self.device_fd, KAPI_MOUNT_FS, ctrl)
            return {
                'status': ctrl.status,
                'message': ctrl.message.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to mount filesystem: {e}")

    def unmount_filesystem(self, path):
        """⚠️ DANGEROUS: Unmount a filesystem"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        ctrl = FSControl()
        ctrl.path = path.encode('utf-8')

        try:
            fcntl.ioctl(self.device_fd, KAPI_UMOUNT_FS, ctrl)
            return {
                'status': ctrl.status,
                'message': ctrl.message.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to unmount filesystem: {e}")

    def inject_kernel_log(self, message, level="INFO"):
        """⚠️ DANGEROUS: Inject a custom log message into kernel log"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        log_inj = LogInjection()
        log_inj.level = level.encode('utf-8')
        log_inj.message = message.encode('utf-8')

        try:
            fcntl.ioctl(self.device_fd, KAPI_INJECT_LOG, log_inj)
            return {
                'status': log_inj.status,
            }
        except OSError as e:
            raise RuntimeError(f"Failed to inject log: {e}")

    def force_memory_reclaim(self):
        """💀 EXTREMELY DANGEROUS: Force kernel memory reclaim (may hang system!)"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        print("⚠️ WARNING: This operation may cause system instability!")
        try:
            fcntl.ioctl(self.device_fd, KAPI_FORCE_PAGE_RECLAIM)
            return {'status': 0}
        except OSError as e:
            raise RuntimeError(f"Failed to force memory reclaim: {e}")

    def set_cpu_affinity(self, pid, cpu_mask):
        """⚠️ DANGEROUS: Set CPU affinity for a process"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        ctrl = CPUControl()
        ctrl.pid = pid
        ctrl.mask = cpu_mask

        try:
            fcntl.ioctl(self.device_fd, KAPI_SET_CPU_AFFINITY, ctrl)
            return {
                'status': ctrl.status,
                'message': ctrl.message.decode('utf-8').strip('\x00'),
            }
        except OSError as e:
            raise RuntimeError(f"Failed to set CPU affinity: {e}")

    def panic_kernel(self):
        """💀💀💀 EXTREMELY DANGEROUS: Trigger kernel panic! WILL CRASH SYSTEM! 💀💀💀"""
        if not self.is_connected():
            raise RuntimeError("Not connected to kernel driver")

        print("💀💀💀 WARNING: THIS WILL CRASH THE ENTIRE SYSTEM! 💀💀💀")
        print("Are you absolutely sure? This is irreversible!")

        try:
            fcntl.ioctl(self.device_fd, KAPI_PANIC_KERNEL)
            # This line will never be reached
            return {'status': 0}
        except OSError as e:
            raise RuntimeError(f"Failed to panic kernel: {e}")

    def get_dangerous_commands(self):
        """Get list of dangerous commands available"""
        return [
            "kill_process",
            "suspend_process",
            "resume_process",
            "load_kernel_module",
            "unload_kernel_module",
            "toggle_network_interface",
            "mount_filesystem",
            "unmount_filesystem",
            "inject_kernel_log",
            "force_memory_reclaim",
            "set_cpu_affinity",
            "panic_kernel"  # 💀
        ]

def format_bytes(bytes_value):
    """Format bytes to human readable format"""
    if bytes_value == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} EB"

def format_time(seconds):
    """Format seconds to human readable format"""
    if seconds < 60:
        return f"{seconds} seconds"
    elif seconds < 3600:
        return f"{seconds//60} minutes, {seconds%60} seconds"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours} hours, {minutes} minutes"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days} days, {hours} hours"

def print_header(title):
    """Print a formatted header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_section(title):
    """Print a formatted section header"""
    print(f"\n--- {title} ---")

def main():
    """Main function demonstrating the enhanced API usage"""
    client = KernelAPIClient()

    print("🚀 Kernel API Client v2.0 - Advanced System Monitor")
    print("=" * 60)

    # Connect to kernel driver
    if not client.connect():
        print("❌ Failed to connect to kernel driver")
        print("\nMake sure to:")
        print("1. Load the kernel module: sudo make -f Makefile.kernel load")
        print("2. Set permissions: sudo chmod 666 /dev/kernel_api_exporter")
        return 1

    try:
        # Test kernel configuration
        print_header("KERNEL CONFIGURATION")
        config = client.get_kernel_config()
        print(f"Kernel Version: {config['version']}")
        print(f"Architecture: {config['arch']}")
        print(f"Page Size: {format_bytes(config['page_size'])}")
        print(f"HZ: {config['hz']}")
        print(f"Compiler: {config['compiler']}")
        print(f"Build Date: {config['build_date']}")

        # Test memory information
        print_header("MEMORY INFORMATION")
        mem_info = client.get_memory_info()
        print(f"Total RAM: {format_bytes(mem_info['total_ram'])}")
        print(f"Free RAM: {format_bytes(mem_info['free_ram'])}")
        print(f"Used RAM: {format_bytes(mem_info['used_ram'])}")
        print(f"Buffers: {format_bytes(mem_info['buffers'])}")
        print(f"Cached: {format_bytes(mem_info['cached'])}")
        print(f"Swap Total: {format_bytes(mem_info['swap_total'])}")
        print(f"Swap Free: {format_bytes(mem_info['swap_free'])}")
        print(f"Slab: {format_bytes(mem_info['slab'])}")
        print(f"Dirty Pages: {format_bytes(mem_info['dirty'])}")
        print(f"Mapped: {format_bytes(mem_info['mapped'])}")

        # Test CPU information
        print_header("CPU INFORMATION")
        cpu_info = client.get_cpu_info()
        print(f"CPU Model: {cpu_info['cpu_model']}")
        print(f"Vendor ID: {cpu_info['vendor_id']}")
        print(f"CPU Family: {cpu_info['cpu_family']}")
        print(f"Total CPUs: {cpu_info['num_cpus']}")
        print(f"Online CPUs: {cpu_info['num_online_cpus']}")
        print(f"Cache Alignment: {cpu_info['cache_alignment']} bytes")
        print(f"System Uptime: {format_time(cpu_info['uptime'])}")

        # Test load average
        print_header("SYSTEM LOAD")
        load = client.get_load_average()
        print(f"Load Average: {load['load1']:.2f} {load['load5']:.2f} {load['load15']:.2f}")
        print(f"Running Tasks: {load['running_tasks']}")
        print(f"Total Tasks: {load['total_tasks']}")

        # Test process information
        print_header("CURRENT PROCESS INFORMATION")
        current_pid = os.getpid()
        proc_info = client.get_process_info(current_pid)
        if proc_info:
            print(f"PID: {proc_info['pid']}")
            print(f"Command: {proc_info['comm']}")
            print(f"Parent PID: {proc_info['ppid']}")
            print(f"Memory Usage: {format_bytes(proc_info['memory_usage'])}")
            print(f"Virtual Size: {format_bytes(proc_info['vsize'])}")
            print(f"RSS: {proc_info['rss']} pages")
            print(f"Number of Threads: {proc_info['num_threads']}")
            print(f"Process State: {proc_info['state']}")
            print(f"Nice Value: {proc_info['nice']}")
            print(f"Priority: {proc_info['priority']}")
        else:
            print(f"Process {current_pid} not found")

        # Test kernel commands
        print_header("KERNEL COMMANDS")
        commands = client.get_all_available_commands()
        for cmd in commands:
            try:
                result = client.execute_kernel_command(cmd)
                print(f"{cmd}: {result['result']}")
            except Exception as e:
                print(f"{cmd}: ERROR - {e}")

        # Test network statistics
        print_header("NETWORK STATISTICS")
        net_stats = client.get_network_stats()
        print(f"RX Packets: {net_stats['rx_packets']:,}")
        print(f"TX Packets: {net_stats['tx_packets']:,}")
        print(f"RX Bytes: {format_bytes(net_stats['rx_bytes'])}")
        print(f"TX Bytes: {format_bytes(net_stats['tx_bytes'])}")
        print(f"RX Errors: {net_stats['rx_errors']}")
        print(f"TX Errors: {net_stats['tx_errors']}")
        print(f"RX Dropped: {net_stats['rx_dropped']}")
        print(f"TX Dropped: {net_stats['tx_dropped']}")

        # Test filesystem information
        print_header("FILESYSTEM INFORMATION")
        fs_info = client.get_filesystem_info()
        print(f"Filesystem Type: {fs_info['fs_type']}")
        print(f"Mount Point: {fs_info['mount_point']}")
        print(f"Device: {fs_info['device_name']}")
        print(f"Total Blocks: {fs_info['total_blocks']:,}")
        print(f"Free Blocks: {fs_info['free_blocks']:,}")
        print(f"Block Size: {format_bytes(fs_info['block_size'])}")
        print(f"Total Inodes: {fs_info['total_inodes']:,}")
        print(f"Free Inodes: {fs_info['free_inodes']:,}")

        # Test shared memory
        print_header("SHARED MEMORY TEST")
        if client.shared_memory:
            try:
                test_data = f"Test data from PID {os.getpid()} at {datetime.now()}"
                client.write_shared_memory(test_data)
                read_data = client.read_shared_memory()
                print(f"Written: {test_data}")
                print(f"Read: {read_data}")
                print("✓ Shared memory working correctly")
            except Exception as e:
                print(f"❌ Shared memory test failed: {e}")
        else:
            print("⚠ Shared memory not available - skipping test")

        # Test netlink communication
        print_header("NETLINK COMMUNICATION TEST")
        try:
            response = client.send_netlink_message("Hello from userland!")
            print(f"Netlink response: {response}")
        except Exception as e:
            print(f"⚠ Netlink test failed: {e}")

        # Export system information
        print_header("SYSTEM INFORMATION EXPORT")
        export_file = client.export_system_info()
        print(f"✓ System information exported to: {export_file}")

        # 🔥 DANGEROUS FUNCTIONS DEMO (BE CAREFUL!)
        print_header("DANGEROUS FUNCTIONS AVAILABLE")
        dangerous_cmds = client.get_dangerous_commands()
        print("⚠️ Available dangerous functions (use with extreme caution!):")
        for i, cmd in enumerate(dangerous_cmds, 1):
            danger_level = "💀💀💀" if cmd == "panic_kernel" else "💀" if cmd == "force_memory_reclaim" else "⚠️"
            print(f"{i:2d}. {danger_level} {cmd}")

        print("\n🔥 Safe demonstration of log injection:")
        try:
            result = client.inject_kernel_log("Hello from KAPI Python client!", "INFO")
            print(f"✓ Log injected successfully (check dmesg)")
        except Exception as e:
            print(f"⚠ Log injection failed: {e}")

        print("\n⚠️ NOTE: Other dangerous functions are available but not demonstrated")
        print("    for safety reasons. Use them only if you know what you're doing!")

    except Exception as e:
        print(f"❌ Error during API testing: {e}")
        return 1

    finally:
        client.disconnect()

    print_header("DEMO COMPLETED SUCCESSFULLY")
    print("🎉 All kernel API functions tested successfully!")
    print("💡 To see injected log: dmesg | grep KAPI_INJECT")
    return 0

if __name__ == "__main__":
    sys.exit(main())

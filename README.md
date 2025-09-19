
# Kernel API Exporter (KAPI) - Technical Documentation

## Table of Contents

1. [Introduction](#introduction)
2. [System Architecture](#system-architecture)
3. [Component Overview](#component-overview)
4. [Installation and Setup](#installation-and-setup)
5. [Kernel Driver Interface](#kernel-driver-interface)
6. [Python Client Library](#python-client-library)
7. [Data Structures](#data-structures)
8. [IOCTL Commands](#ioctl-commands)
9. [Communication Protocols](#communication-protocols)
10. [Memory Management](#memory-management)
11. [Security Considerations](#security-considerations)
12. [Error Handling](#error-handling)
13. [Performance Characteristics](#performance-characteristics)
14. [Kernel Compatibility](#kernel-compatibility)
15. [API Reference](#api-reference)
16. [Troubleshooting](#troubleshooting)
17. [Implementation Details](#implementation-details)

## Introduction

The Kernel API Exporter (KAPI) is a comprehensive kernel-space to user-space communication framework designed for Linux operating systems. The system provides direct access to kernel subsystems through a character device interface, enabling applications to retrieve system information, monitor kernel state, and perform privileged operations that are typically restricted to kernel modules.

### Purpose and Scope

KAPI serves as a bridge between user-space applications and kernel-space functionality, offering capabilities that extend beyond traditional system call interfaces. The framework is designed for system monitoring, debugging, research, and administrative tasks that require deep kernel integration.

### Key Features

- Direct kernel memory access
- Real-time system monitoring
- Process management capabilities
- Network interface control
- Filesystem operations
- Kernel module management
- Physical memory manipulation
- Virtual-to-physical address translation
- Shared memory communication
- Netlink socket interface

## System Architecture

### Overview

The KAPI system consists of three primary components:

1. **Kernel Driver Module** (`kernel_driver.c`): A loadable kernel module that implements the core functionality
2. **Python Client Library** (`kapi_client.py`): A comprehensive user-space interface
3. **Build System** (`Makefile`, `Makefile.kernel`): Compilation and installation infrastructure

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    User Space                               │
├─────────────────────────────────────────────────────────────┤
│  Python Client Application                                  │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   IOCTL Calls   │  │  Shared Memory  │                  │
│  └─────────────────┘  └─────────────────┘                  │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │  Netlink Socket │  │  Character Dev  │                  │
│  └─────────────────┘  └─────────────────┘                  │
├─────────────────────────────────────────────────────────────┤
│                  System Call Interface                     │
├─────────────────────────────────────────────────────────────┤
│                    Kernel Space                            │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              KAPI Driver Module                         │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐      │ │
│  │  │   Memory    │ │   Process   │ │   Network   │      │ │
│  │  │ Management  │ │ Management  │ │ Management  │      │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘      │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐      │ │
│  │  │ Filesystem  │ │   Module    │ │   Hardware  │      │ │
│  │  │ Operations  │ │ Management  │ │   Access    │      │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘      │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Hardware Layer                          │
└─────────────────────────────────────────────────────────────┘
```

### Communication Flow

1. **Character Device Interface**: Primary communication channel using IOCTL commands
2. **Shared Memory**: High-performance data transfer mechanism
3. **Netlink Socket**: Asynchronous messaging system
4. **Direct Memory Access**: Physical memory read/write operations

## Component Overview

### Kernel Driver Module

The kernel driver module (`kernel_driver.c`) implements the core KAPI functionality as a loadable kernel module (LKM). It provides:

- Character device registration and management
- IOCTL command processing
- Memory management subsystem interface
- Process monitoring and control
- Network subsystem integration
- Filesystem operation support
- Physical memory access capabilities

### Python Client Library

The Python client library (`kapi_client.py`) provides a comprehensive user-space interface that abstracts the complexity of kernel communication. Features include:

- High-level API functions
- Data structure marshaling
- Error handling and validation
- Memory management utilities
- Networking capabilities
- System information exporters

### Build System

The build system consists of two Makefiles:

- `Makefile`: Standard kernel module build configuration
- `Makefile.kernel`: Extended build system with additional compiler flags

## Installation and Setup

### Prerequisites

- Linux kernel headers (matching running kernel version)
- GNU Make
- GCC compiler
- Python 3.x
- Root privileges for module loading

### Compilation Process

```bash
# Build the kernel module
make -f Makefile.kernel all

# Load the module and set permissions
make -f Makefile.kernel load
```

### Verification

After successful installation, the following should be available:

- Character device: `/dev/kernel_api_exporter`
- Kernel module: Listed in `lsmod` output
- Device permissions: Read/write access for target users

### Uninstallation

```bash
# Unload the module
make -f Makefile.kernel uninstall

# Clean build artifacts
make -f Makefile.kernel clean
```

## Kernel Driver Interface

### Character Device Operations

The kernel driver registers a character device that supports the following operations:

#### File Operations Structure

```c
static struct file_operations fops = {
    .open = device_open,
    .read = device_read,
    .write = device_write,
    .release = device_release,
    .unlocked_ioctl = device_ioctl,
    .mmap = device_mmap,
};
```

#### Device Open Operation

- **Function**: `device_open()`
- **Purpose**: Initialize device session
- **Returns**: 0 on success, negative error code on failure
- **Side Effects**: Logs opening PID to kernel log

#### Device Read Operation

- **Function**: `device_read()`
- **Purpose**: Read data from shared buffer
- **Parameters**: File descriptor, buffer, length, offset
- **Returns**: Number of bytes read or negative error code
- **Behavior**: Supports partial reads and offset-based access

#### Device Write Operation

- **Function**: `device_write()`
- **Purpose**: Write data to shared buffer
- **Parameters**: File descriptor, buffer, length, offset
- **Returns**: Number of bytes written or negative error code
- **Behavior**: Supports partial writes and offset-based access

#### Device IOCTL Operation

- **Function**: `device_ioctl()`
- **Purpose**: Execute control commands
- **Parameters**: File descriptor, command, argument pointer
- **Returns**: Command-specific return value
- **Behavior**: Dispatches to command-specific handlers

#### Device Memory Map Operation

- **Function**: `device_mmap()`
- **Purpose**: Map shared buffer to user space
- **Parameters**: File descriptor, VMA structure
- **Returns**: 0 on success, negative error code on failure
- **Behavior**: Maps 16KB shared buffer with appropriate flags

#### Device Release Operation

- **Function**: `device_release()`
- **Purpose**: Clean up device session
- **Returns**: 0 on success
- **Side Effects**: Logs closing PID to kernel log

### Shared Memory Management

The driver allocates a 16KB shared buffer using `__get_free_pages()` with the following characteristics:

- **Size**: 16,384 bytes (4 pages)
- **Alignment**: Page-aligned physical address
- **Flags**: `GFP_KERNEL | __GFP_ZERO`
- **Protection**: Pages marked as reserved
- **Mapping**: Supports user-space memory mapping

### Netlink Socket Interface

The driver creates a netlink socket for asynchronous communication:

- **Protocol**: NETLINK_USER (31)
- **Message Format**: Standard netlink message header + payload
- **Direction**: Bidirectional communication
- **Usage**: Status notifications and asynchronous data transfer

## Python Client Library

### Class Structure

The main interface is provided by the `KernelAPIClient` class, which encapsulates all communication with the kernel driver.

#### Initialization

```python
client = KernelAPIClient()
```

#### Connection Management

- **Method**: `connect()`
- **Purpose**: Establish connection to kernel driver
- **Returns**: Boolean success status
- **Operations**: Opens character device, creates netlink socket, maps shared memory

- **Method**: `disconnect()`
- **Purpose**: Clean up all connections
- **Returns**: None
- **Operations**: Closes all file descriptors and unmaps memory

- **Method**: `is_connected()`
- **Purpose**: Check connection status
- **Returns**: Boolean connection state

#### Information Retrieval Methods

##### Memory Information
- **Method**: `get_memory_info()`
- **Returns**: Dictionary with comprehensive memory statistics
- **Data Source**: `/proc/meminfo` equivalent kernel data

##### CPU Information
- **Method**: `get_cpu_info()`
- **Returns**: Dictionary with CPU specifications and statistics
- **Data Source**: Kernel CPU subsystem

##### Process Information
- **Method**: `get_process_info(pid)`
- **Parameters**: Process ID
- **Returns**: Dictionary with process details or None if not found
- **Data Source**: Task structure in kernel

##### Network Statistics
- **Method**: `get_network_stats()`
- **Returns**: Dictionary with network interface statistics
- **Data Source**: Network device statistics

##### Filesystem Information
- **Method**: `get_filesystem_info()`
- **Returns**: Dictionary with filesystem metadata
- **Data Source**: VFS layer information

##### Load Average
- **Method**: `get_load_average()`
- **Returns**: Dictionary with system load metrics
- **Data Source**: Kernel scheduler statistics

##### Kernel Configuration
- **Method**: `get_kernel_config()`
- **Returns**: Dictionary with kernel build and runtime configuration
- **Data Source**: Kernel configuration symbols

#### Kernel Command Execution

- **Method**: `execute_kernel_command(command)`
- **Parameters**: Command string
- **Returns**: Dictionary with command result
- **Supported Commands**: 
  - `get_kernel_version`
  - `get_uptime`
  - `get_hostname`
  - `get_domainname`
  - `get_total_memory`
  - `get_free_memory`
  - `get_cpu_count`
  - `get_page_size`
  - `get_hz`
  - `get_jiffies`

#### Communication Methods

##### Shared Memory Operations
- **Method**: `write_shared_memory(data, offset=0)`
- **Purpose**: Write data to shared memory buffer
- **Parameters**: Data bytes/string, optional offset
- **Returns**: None (raises exception on error)

- **Method**: `read_shared_memory(size=None, offset=0)`
- **Purpose**: Read data from shared memory buffer
- **Parameters**: Optional size limit, optional offset
- **Returns**: String data

##### Netlink Communication
- **Method**: `send_netlink_message(message)`
- **Purpose**: Send message via netlink socket
- **Parameters**: Message string
- **Returns**: Response string

#### System Control Methods (High Risk)

##### Process Control
- **Method**: `kill_process(pid, signal=9)`
- **Purpose**: Send signal to process
- **Parameters**: Process ID, signal number
- **Returns**: Status dictionary

- **Method**: `suspend_process(pid)`
- **Purpose**: Suspend process (SIGSTOP)
- **Parameters**: Process ID
- **Returns**: Status dictionary

- **Method**: `resume_process(pid)`
- **Purpose**: Resume process (SIGCONT)
- **Parameters**: Process ID
- **Returns**: Status dictionary

##### Module Management
- **Method**: `load_kernel_module(path, params="")`
- **Purpose**: Load kernel module
- **Parameters**: Module path, optional parameters
- **Returns**: Status dictionary

- **Method**: `unload_kernel_module(name)`
- **Purpose**: Unload kernel module
- **Parameters**: Module name
- **Returns**: Status dictionary

##### Network Control
- **Method**: `toggle_network_interface(interface, up=True)`
- **Purpose**: Bring network interface up or down
- **Parameters**: Interface name, up/down boolean
- **Returns**: Status dictionary

##### Filesystem Operations
- **Method**: `mount_filesystem(device, path, fs_type="ext4", options="")`
- **Purpose**: Mount filesystem
- **Parameters**: Device, mount point, filesystem type, options
- **Returns**: Status dictionary

- **Method**: `unmount_filesystem(path)`
- **Purpose**: Unmount filesystem
- **Parameters**: Mount point path
- **Returns**: Status dictionary

##### System Operations
- **Method**: `inject_kernel_log(message, level="INFO")`
- **Purpose**: Inject message into kernel log
- **Parameters**: Message string, log level
- **Returns**: Status dictionary

- **Method**: `force_memory_reclaim()`
- **Purpose**: Force kernel memory reclamation
- **Returns**: Status dictionary
- **Warning**: May cause system instability

- **Method**: `set_cpu_affinity(pid, cpu_mask)`
- **Purpose**: Set process CPU affinity
- **Parameters**: Process ID, CPU mask
- **Returns**: Status dictionary

#### Physical Memory Operations (Extreme Risk)

##### Memory Access
- **Method**: `read_physical_memory(phys_addr, size)`
- **Purpose**: Read from physical memory address
- **Parameters**: Physical address, size (max 4KB)
- **Returns**: Dictionary with status and data

- **Method**: `write_physical_memory(phys_addr, data)`
- **Purpose**: Write to physical memory address
- **Parameters**: Physical address, data bytes
- **Returns**: Status dictionary
- **Warning**: Can corrupt system memory

##### Address Translation
- **Method**: `virtual_to_physical(virt_addr, pid=0)`
- **Purpose**: Convert virtual to physical address
- **Parameters**: Virtual address, process ID (0 for kernel)
- **Returns**: Dictionary with translated address

##### Memory Patching
- **Method**: `patch_memory(phys_addr, patch_data, restore=False, original_data=None)`
- **Purpose**: Patch physical memory with backup/restore capability
- **Parameters**: Physical address, patch data, restore flag, original data
- **Returns**: Dictionary with status and original data
- **Warning**: Can cause system instability

#### System Destruction (Maximum Risk)

- **Method**: `panic_kernel()`
- **Purpose**: Trigger immediate kernel panic
- **Returns**: Never returns (system crash)
- **Warning**: Immediately crashes entire system

#### Utility Methods

##### Export Functions
- **Method**: `export_system_info(filename=None)`
- **Purpose**: Export comprehensive system information to JSON
- **Parameters**: Optional filename
- **Returns**: Generated filename

##### Helper Functions
- **Method**: `get_all_available_commands()`
- **Purpose**: List all available kernel commands
- **Returns**: List of command strings

- **Method**: `get_dangerous_commands()`
- **Purpose**: List all dangerous/destructive commands
- **Returns**: List of dangerous command names

## Data Structures

### Memory Information Structure

```c
struct memory_info {
    unsigned long total_ram;      // Total RAM in bytes
    unsigned long free_ram;       // Free RAM in bytes
    unsigned long used_ram;       // Used RAM in bytes
    unsigned long buffers;        // Buffer cache in bytes
    unsigned long cached;         // Page cache in bytes
    unsigned long swap_total;     // Total swap in bytes
    unsigned long swap_free;      // Free swap in bytes
    unsigned long slab;           // Slab allocator usage
    unsigned long page_tables;    // Page table overhead
    unsigned long vmalloc_used;   // vmalloc area usage
    unsigned long committed_as;   // Committed memory
    unsigned long dirty;          // Dirty pages
    unsigned long writeback;      // Pages under writeback
    unsigned long anon_pages;     // Anonymous pages
    unsigned long mapped;         // Memory-mapped pages
    unsigned long shmem;          // Shared memory pages
};
```

### CPU Information Structure

```c
struct cpu_info {
    unsigned int num_cpus;        // Number of possible CPUs
    unsigned int num_online_cpus; // Number of online CPUs
    unsigned long cpu_freq;       // CPU frequency
    char cpu_model[64];           // CPU model string
    unsigned long uptime;         // System uptime in seconds
    unsigned long idle_time;      // Idle time
    unsigned long user_time;      // User mode time
    unsigned long system_time;    // System mode time
    unsigned long iowait_time;    // I/O wait time
    unsigned long irq_time;       // IRQ handling time
    unsigned long softirq_time;   // Software IRQ time
    unsigned long guest_time;     // Guest VM time
    unsigned int cache_size;      // Cache size
    unsigned int cache_alignment; // Cache line alignment
    char vendor_id[16];           // CPU vendor identifier
    char cpu_family[16];          // CPU family
};
```

### Process Information Structure

```c
struct process_info {
    int pid;                      // Process ID
    char comm[16];                // Process command name
    unsigned long memory_usage;   // Memory usage in bytes
    unsigned int cpu_usage;       // CPU usage percentage
    int num_threads;              // Number of threads
    int ppid;                     // Parent process ID
    int pgrp;                     // Process group ID
    int session;                  // Session ID
    int tty_nr;                   // TTY number
    unsigned long start_time;     // Process start time
    unsigned long vsize;          // Virtual memory size
    long rss;                     // Resident set size
    unsigned long rsslim;         // RSS limit
    unsigned long priority;       // Process priority
    long nice;                    // Nice value
    unsigned long num_threads_full; // Full thread count
    char state;                   // Process state
    unsigned int flags;           // Process flags
};
```

### Network Statistics Structure

```c
struct network_stats {
    unsigned long rx_packets;     // Received packets
    unsigned long tx_packets;     // Transmitted packets
    unsigned long rx_bytes;       // Received bytes
    unsigned long tx_bytes;       // Transmitted bytes
    unsigned long rx_errors;      // Receive errors
    unsigned long tx_errors;      // Transmit errors
    unsigned long rx_dropped;     // Dropped received packets
    unsigned long tx_dropped;     // Dropped transmitted packets
    unsigned long multicast;      // Multicast packets
    unsigned long collisions;     // Collision count
    unsigned long rx_length_errors; // Length errors
    unsigned long rx_over_errors;   // Overrun errors
    unsigned long rx_crc_errors;    // CRC errors
    unsigned long rx_frame_errors;  // Frame errors
    unsigned long rx_fifo_errors;   // FIFO errors
    unsigned long rx_missed_errors; // Missed errors
    unsigned long tx_aborted_errors; // Aborted transmissions
    unsigned long tx_carrier_errors; // Carrier errors
    unsigned long tx_fifo_errors;    // FIFO errors
    unsigned long tx_heartbeat_errors; // Heartbeat errors
    unsigned long tx_window_errors;   // Window errors
};
```

### Control Structures

#### Process Control Structure
```c
struct process_control {
    int pid;                      // Target process ID
    int signal;                   // Signal to send
    int status;                   // Operation status
    char message[256];            // Status message
};
```

#### Module Control Structure
```c
struct module_control {
    char path[256];               // Module file path
    char name[64];                // Module name
    char params[256];             // Module parameters
    int status;                   // Operation status
    char message[256];            // Status message
};
```

#### Physical Memory Structures
```c
struct phys_mem_read {
    unsigned long phys_addr;      // Physical address
    unsigned long size;           // Read size (max 4KB)
    char data[4096];              // Read data buffer
    int status;                   // Operation status
    char message[256];            // Status message
};

struct phys_mem_write {
    unsigned long phys_addr;      // Physical address
    unsigned long size;           // Write size (max 4KB)
    char data[4096];              // Write data buffer
    int status;                   // Operation status
    char message[256];            // Status message
};

struct virt_to_phys {
    unsigned long virt_addr;      // Virtual address
    int pid;                      // Process ID (0 for kernel)
    unsigned long phys_addr;      // Resulting physical address
    int status;                   // Operation status
    char message[256];            // Status message
};

struct mem_patch {
    unsigned long phys_addr;      // Physical address to patch
    unsigned long size;           // Patch size (max 4KB)
    char original_data[4096];     // Original data backup
    char patch_data[4096];        // Patch data
    int restore;                  // 0=patch, 1=restore
    int status;                   // Operation status
    char message[256];            // Status message
};
```

## IOCTL Commands

### Command Definition

IOCTL commands are defined using the Linux kernel's standard IOCTL macros:

```c
#define KAPI_IOC_MAGIC 'k'
#define KAPI_IOC_MAXNR 30
```

### Information Retrieval Commands

| Command | Code | Type | Structure | Purpose |
|---------|------|------|-----------|---------|
| `KAPI_GET_MEMORY_INFO` | 1 | `_IOR` | `memory_info` | Retrieve memory statistics |
| `KAPI_GET_CPU_INFO` | 2 | `_IOR` | `cpu_info` | Retrieve CPU information |
| `KAPI_GET_PROCESS_INFO` | 3 | `_IOWR` | `process_info` | Retrieve process details |
| `KAPI_EXECUTE_KERNEL_CMD` | 4 | `_IOWR` | `kernel_cmd` | Execute kernel command |
| `KAPI_GET_NETWORK_STATS` | 5 | `_IOR` | `network_stats` | Retrieve network statistics |
| `KAPI_GET_FILE_SYSTEM_INFO` | 6 | `_IOR` | `filesystem_info` | Retrieve filesystem info |
| `KAPI_GET_LOADAVG` | 9 | `_IOR` | `loadavg_info` | Retrieve load average |
| `KAPI_GET_KERNEL_CONFIG` | 10 | `_IOR` | `kernel_config` | Retrieve kernel config |

### System Control Commands

| Command | Code | Type | Structure | Purpose |
|---------|------|------|-----------|---------|
| `KAPI_KILL_PROCESS` | 15 | `_IOW` | `process_control` | Send signal to process |
| `KAPI_SUSPEND_PROCESS` | 16 | `_IOW` | `process_control` | Suspend process |
| `KAPI_RESUME_PROCESS` | 17 | `_IOW` | `process_control` | Resume process |
| `KAPI_LOAD_MODULE` | 18 | `_IOW` | `module_control` | Load kernel module |
| `KAPI_UNLOAD_MODULE` | 19 | `_IOW` | `module_control` | Unload kernel module |
| `KAPI_TOGGLE_INTERFACE` | 20 | `_IOW` | `net_control` | Toggle network interface |
| `KAPI_MOUNT_FS` | 21 | `_IOW` | `fs_control` | Mount filesystem |
| `KAPI_UMOUNT_FS` | 22 | `_IOW` | `fs_control` | Unmount filesystem |
| `KAPI_INJECT_LOG` | 23 | `_IOW` | `log_injection` | Inject kernel log message |
| `KAPI_FORCE_PAGE_RECLAIM` | 24 | `_IO` | None | Force memory reclamation |
| `KAPI_SET_CPU_AFFINITY` | 25 | `_IOW` | `cpu_control` | Set CPU affinity |

### High-Risk Commands

| Command | Code | Type | Structure | Purpose |
|---------|------|------|-----------|---------|
| `KAPI_PANIC_KERNEL` | 26 | `_IO` | None | Trigger kernel panic |
| `KAPI_READ_PHYS_MEM` | 27 | `_IOWR` | `phys_mem_read` | Read physical memory |
| `KAPI_WRITE_PHYS_MEM` | 28 | `_IOW` | `phys_mem_write` | Write physical memory |
| `KAPI_VIRT_TO_PHYS` | 29 | `_IOWR` | `virt_to_phys` | Virtual to physical translation |
| `KAPI_PATCH_MEMORY` | 30 | `_IOWR` | `mem_patch` | Patch physical memory |

### IOCTL Direction Types

- `_IOR`: Read data from kernel to user
- `_IOW`: Write data from user to kernel
- `_IOWR`: Read and write data (bidirectional)
- `_IO`: No data transfer

## Communication Protocols

### Character Device Protocol

1. **Device Opening**: User opens `/dev/kernel_api_exporter`
2. **Command Execution**: User issues IOCTL commands with appropriate structures
3. **Data Transfer**: Kernel copies data to/from user space
4. **Error Handling**: Kernel returns appropriate error codes
5. **Device Closing**: User closes file descriptor

### Shared Memory Protocol

1. **Memory Mapping**: User maps device memory using `mmap()`
2. **Data Writing**: User writes data directly to mapped region
3. **Synchronization**: User calls `flush()` to ensure data visibility
4. **Data Reading**: User reads data directly from mapped region
5. **Unmapping**: User unmaps memory when finished

### Netlink Protocol

1. **Socket Creation**: User creates netlink socket with `NETLINK_USER` protocol
2. **Message Formatting**: User constructs netlink message with header
3. **Message Transmission**: User sends message to kernel
4. **Response Reception**: User receives response from kernel
5. **Socket Closure**: User closes netlink socket

## Memory Management

### Shared Buffer Allocation

The kernel driver allocates a 16KB shared buffer with the following characteristics:

#### Allocation Method
```c
shared_buffer = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(buffer_size));
shared_buffer_phys = virt_to_phys(shared_buffer);
```

#### Buffer Properties
- **Size**: 16,384 bytes (4 × 4KB pages)
- **Alignment**: Page-aligned physical address
- **Flags**: `GFP_KERNEL` (kernel memory) + `__GFP_ZERO` (zero-initialized)
- **Protection**: Pages marked as reserved to prevent swapping

#### Page Reservation
```c
for (i = 0; i < (buffer_size >> PAGE_SHIFT); i++) {
    SetPageReserved(virt_to_page(addr));
    addr += PAGE_SIZE;
}
```

### Memory Mapping to User Space

The driver supports memory mapping with the following configuration:

#### VMA Flags
- `VM_IO`: Indicates I/O memory region
- `VM_DONTEXPAND`: Prevents VMA expansion
- `VM_DONTDUMP`: Excludes from core dumps

#### Page Protection
- Uses `pgprot_noncached()` for consistent data sharing
- Prevents CPU caching of shared data

#### Mapping Process
1. Validate mapping size and alignment
2. Calculate physical frame number (PFN)
3. Set appropriate VMA flags
4. Call `remap_pfn_range()` to establish mapping

### Physical Memory Access

The driver provides direct physical memory access capabilities:

#### Address Validation
```c
if (!pfn_valid(phys_addr >> PAGE_SHIFT)) {
    return -EINVAL;
}
```

#### Virtual Mapping
```c
virt_addr = phys_to_virt(phys_addr);
```

#### Data Transfer
- Read operations: `memcpy(user_buffer, virt_addr, size)`
- Write operations: `memcpy(virt_addr, user_data, size)`

### Virtual-to-Physical Translation

The driver implements page table walking for address translation:

#### Kernel 6.x Compatibility
The implementation includes compatibility macros for different kernel versions:

```c
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    #define KAPI_PTE_OFFSET_MAP(pmd, addr) pte_offset_kernel(pmd, addr)
    #define KAPI_PTE_UNMAP(pte) do { } while(0)
#else
    #define KAPI_PTE_OFFSET_MAP(pmd, addr) pte_offset_map(pmd, addr)
    #define KAPI_PTE_UNMAP(pte) pte_unmap(pte)
#endif
```

#### Page Table Walking Process
1. Obtain process memory descriptor
2. Walk through page directory levels (PGD → P4D → PUD → PMD → PTE)
3. Extract physical frame number from PTE
4. Calculate final physical address

#### Alternative Method for Newer Kernels
For kernel 6.x compatibility, an alternative implementation uses `get_user_pages_remote()`:

```c
ret = get_user_pages_remote(mm, virt_addr, 1, FOLL_GET, &page, NULL);
phys = page_to_phys(page) + (virt_addr & ~PAGE_MASK);
```

## Security Considerations

### Privilege Requirements

The KAPI system requires elevated privileges due to its direct kernel access capabilities:

- **Module Loading**: Requires `CAP_SYS_MODULE` capability
- **Device Access**: Requires appropriate file permissions
- **Physical Memory**: Requires `CAP_SYS_RAWIO` capability
- **Process Control**: Requires `CAP_KILL` and `CAP_SYS_PTRACE`

### Attack Surface

The KAPI system exposes significant attack surface:

#### Direct Kernel Access
- Physical memory read/write capabilities
- Kernel data structure manipulation
- Page table modification potential

#### Process Control
- Arbitrary signal delivery
- Process suspension/resumption
- CPU affinity manipulation

#### System Control
- Network interface manipulation
- Filesystem mount/unmount operations
- Kernel module loading/unloading

### Risk Categories

#### Low Risk Operations
- Memory statistics retrieval
- CPU information queries
- Process information lookup
- Network statistics reading

#### Medium Risk Operations
- Kernel command execution
- Shared memory operations
- Netlink communication
- Log injection

#### High Risk Operations
- Process signal delivery
- Network interface control
- Filesystem operations
- Module management

#### Extreme Risk Operations
- Physical memory access
- Memory patching
- Kernel panic trigger
- Direct hardware access

### Mitigation Strategies

#### Access Control
- Implement proper file permissions on device node
- Use capability-based access control
- Audit all privileged operations

#### Input Validation
- Validate all user-provided addresses
- Check buffer sizes and alignments
- Sanitize string inputs

#### Error Handling
- Implement comprehensive error checking
- Log all operations for audit trail
- Handle exceptional conditions gracefully

#### Resource Management
- Limit memory allocation sizes
- Implement operation timeouts
- Clean up resources on failure

## Error Handling

### Error Code Categories

The KAPI system uses standard Linux error codes:

#### Memory Errors
- `ENOMEM`: Insufficient memory
- `EFAULT`: Bad address
- `EINVAL`: Invalid argument
- `ENOSPC`: No space left on device

#### Process Errors
- `ESRCH`: No such process
- `EPERM`: Operation not permitted
- `EACCES`: Permission denied

#### Device Errors
- `ENODEV`: No such device
- `EBUSY`: Device busy
- `EIO`: I/O error

#### Network Errors
- `ENETDOWN`: Network is down
- `ENONET`: Machine is not on network
- `ECONNREFUSED`: Connection refused

### Error Reporting Mechanism

#### Kernel Space
- Return negative error codes
- Log errors to kernel message buffer
- Update status fields in data structures

#### User Space
- Raise Python exceptions with descriptive messages
- Return status dictionaries with error details
- Implement error code translation

### Error Recovery Strategies

#### Retry Logic
- Implement automatic retry for transient errors
- Use exponential backoff for repeated failures
- Limit maximum retry attempts

#### Graceful Degradation
- Disable unsafe operations on error
- Fall back to alternative data sources
- Continue operation with reduced functionality

#### Resource Cleanup
- Release allocated memory on error
- Close file descriptors
- Unmap memory regions

## Performance Characteristics

### Throughput Metrics

#### Character Device Operations
- **IOCTL Latency**: 10-100 microseconds per command
- **Data Transfer Rate**: 50-100 MB/s for bulk operations
- **Concurrent Operations**: Limited by kernel scheduling

#### Shared Memory Operations
- **Access Latency**: Near-zero (direct memory access)
- **Transfer Rate**: Memory bandwidth limited
- **Synchronization Overhead**: Minimal

#### Netlink Operations
- **Message Latency**: 100-1000 microseconds
- **Throughput**: 10-50 MB/s
- **Queue Depth**: Kernel buffer limited

### Memory Usage

#### Kernel Space
- **Driver Code**: ~50KB
- **Shared Buffer**: 16KB
- **Per-Connection Overhead**: <1KB

#### User Space
- **Python Library**: ~500KB
- **Data Structures**: <10KB
- **Buffer Overhead**: 16KB (mapped)

### CPU Overhead

#### Information Retrieval
- **Memory Info**: <1ms CPU time
- **Process Info**: <5ms CPU time
- **Network Stats**: <2ms CPU time

#### Control Operations
- **Process Control**: <10ms CPU time
- **Module Operations**: 100ms-1s CPU time
- **Filesystem Operations**: 10-100ms CPU time

### Scalability Limitations

#### Concurrent Access
- Single character device instance
- Shared buffer contention
- Kernel lock contention

#### Memory Constraints
- Fixed 16KB shared buffer
- Limited physical memory access (4KB chunks)
- Page allocation limitations

#### Process Limitations
- Single kernel module instance
- Limited netlink socket capacity
- System call overhead

## Kernel Compatibility

### Supported Kernel Versions

The KAPI system supports Linux kernels from version 5.0 to 6.8+:

#### Version-Specific Adaptations

##### Kernel 5.x Series
- Standard PTE mapping functions
- Traditional page table walking
- Classic memory management APIs

##### Kernel 6.x Series
- Enhanced PTE offset functions
- Modified page table access patterns
- Updated memory management interfaces

##### Kernel 6.5+ Specific Changes
- `pte_offset_kernel()` instead of `pte_offset_map()`
- Simplified PTE unmapping
- Updated VMA flag handling

### Compatibility Macros

```c
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    #define KAPI_PTE_OFFSET_MAP(pmd, addr) pte_offset_kernel(pmd, addr)
    #define KAPI_PTE_UNMAP(pte) do { } while(0)
    #define KAPI_HAS_NEW_PTE_API 1
#else
    #define KAPI_PTE_OFFSET_MAP(pmd, addr) pte_offset_map(pmd, addr)
    #define KAPI_PTE_UNMAP(pte) pte_unmap(pte)
    #define KAPI_HAS_NEW_PTE_API 0
#endif
```

### API Evolution Handling

#### Memory Management
- Conditional compilation for different VM statistics APIs
- Version-specific page table walking implementations
- Compatibility wrappers for memory allocation functions

#### Process Management
- Adaptation to task structure changes
- Updated process statistics interfaces
- Modified signal delivery mechanisms

#### Network Subsystem
- Device statistics structure evolution
- Interface control API changes
- Netlink protocol updates

### Build System Compatibility

#### Compiler Flags
```makefile
EXTRA_CFLAGS := -Wno-error=date-time -Wno-error=enum-conversion
```

#### Kernel Header Dependencies
- Automatic kernel version detection
- Conditional header inclusion
- Feature availability checking

## API Reference

### KernelAPIClient Class Methods

#### Connection Management

##### `connect() -> bool`
Establishes connection to kernel driver.

**Returns:**
- `True`: Connection successful
- `False`: Connection failed

**Exceptions:**
- `RuntimeError`: Connection failure

**Example Usage:**
```python
client = KernelAPIClient()
if client.connect():
    print("Connected successfully")
else:
    print("Connection failed")
```

##### `disconnect() -> None`
Closes all connections and cleans up resources.

**Side Effects:**
- Closes character device
- Unmaps shared memory
- Closes netlink socket

##### `is_connected() -> bool`
Checks current connection status.

**Returns:**
- `True`: Client is connected
- `False`: Client is not connected

#### Information Retrieval

##### `get_memory_info() -> dict`
Retrieves comprehensive system memory information.

**Returns:**
Dictionary containing:
- `total_ram`: Total RAM in bytes
- `free_ram`: Free RAM in bytes
- `used_ram`: Used RAM in bytes
- `buffers`: Buffer cache in bytes
- `cached`: Page cache in bytes
- `swap_total`: Total swap space in bytes
- `swap_free`: Free swap space in bytes
- Additional memory statistics

**Exceptions:**
- `RuntimeError`: Not connected or IOCTL failure

##### `get_cpu_info() -> dict`
Retrieves comprehensive CPU information.

**Returns:**
Dictionary containing:
- `num_cpus`: Total number of CPUs
- `num_online_cpus`: Number of online CPUs
- `cpu_model`: CPU model string
- `vendor_id`: CPU vendor identifier
- `uptime`: System uptime in seconds
- Additional CPU statistics

##### `get_process_info(pid: int) -> dict | None`
Retrieves detailed information about a specific process.

**Parameters:**
- `pid`: Process ID to query

**Returns:**
- Dictionary with process information if found
- `None` if process not found

**Dictionary Contents:**
- `pid`: Process ID
- `comm`: Command name
- `memory_usage`: Memory usage in bytes
- `ppid`: Parent process ID
- `state`: Process state character
- Additional process details

##### `get_load_average() -> dict`
Retrieves system load average information.

**Returns:**
Dictionary containing:
- `load1`: 1-minute load average
- `load5`: 5-minute load average
- `load15`: 15-minute load average
- `running_tasks`: Number of running tasks
- `total_tasks`: Total number of tasks

#### Communication Methods

##### `send_netlink_message(message: str) -> str`
Sends message via netlink socket and receives response.

**Parameters:**
- `message`: Message string to send

**Returns:**
- Response string from kernel

**Exceptions:**
- `RuntimeError`: Netlink communication failure

##### `write_shared_memory(data: str | bytes, offset: int = 0) -> None`
Writes data to shared memory buffer.

**Parameters:**
- `data`: Data to write (string or bytes)
- `offset`: Offset in buffer (default: 0)

**Exceptions:**
- `RuntimeError`: Shared memory not available or write failure

##### `read_shared_memory(size: int = None, offset: int = 0) -> str`
Reads data from shared memory buffer.

**Parameters:**
- `size`: Number of bytes to read (default: entire buffer)
- `offset`: Offset in buffer (default: 0)

**Returns:**
- String data from shared memory

#### System Control Methods

##### `kill_process(pid: int, signal: int = 9) -> dict`
Sends signal to specified process.

**Parameters:**
- `pid`: Target process ID
- `signal`: Signal number (default: SIGKILL)

**Returns:**
Dictionary containing:
- `status`: Operation status code
- `message`: Status message

**Risk Level:** High

##### `inject_kernel_log(message: str, level: str = "INFO") -> dict`
Injects custom message into kernel log.

**Parameters:**
- `message`: Log message text
- `level`: Log level (INFO, WARNING, ERROR, etc.)

**Returns:**
Dictionary containing:
- `status`: Operation status code

**Risk Level:** Medium

#### Physical Memory Operations

##### `read_physical_memory(phys_addr: int, size: int) -> dict`
Reads data from physical memory address.

**Parameters:**
- `phys_addr`: Physical address to read from
- `size`: Number of bytes to read (maximum 4KB)

**Returns:**
Dictionary containing:
- `status`: Operation status code
- `message`: Status message
- `data`: Read data as bytes

**Risk Level:** Extreme

##### `write_physical_memory(phys_addr: int, data: bytes) -> dict`
Writes data to physical memory address.

**Parameters:**
- `phys_addr`: Physical address to write to
- `data`: Data bytes to write (maximum 4KB)

**Returns:**
Dictionary containing:
- `status`: Operation status code
- `message`: Status message

**Risk Level:** Extreme

##### `virtual_to_physical(virt_addr: int, pid: int = 0) -> dict`
Converts virtual address to physical address.

**Parameters:**
- `virt_addr`: Virtual address to convert
- `pid`: Process ID (0 for kernel addresses)

**Returns:**
Dictionary containing:
- `virtual_address`: Input virtual address
- `physical_address`: Converted physical address
- `status`: Operation status code
- `message`: Status message

**Risk Level:** High

#### Utility Functions

##### `format_bytes(bytes_value: int) -> str`
Formats byte value to human-readable string.

**Parameters:**
- `bytes_value`: Number of bytes

**Returns:**
- Formatted string (e.g., "1.5 GB")

##### `format_time(seconds: int) -> str`
Formats seconds to human-readable time string.

**Parameters:**
- `seconds`: Time in seconds

**Returns:**
- Formatted time string (e.g., "2 hours, 30 minutes")

### Global Functions

##### `print_header(title: str) -> None`
Prints formatted header for output sections.

##### `print_section(title: str) -> None`
Prints formatted section header.

## Troubleshooting

### Common Issues

#### Module Loading Failures

**Symptom:** `insmod` fails with "Operation not permitted"
**Cause:** Insufficient privileges or secure boot enabled
**Solution:**
- Use `sudo` for module loading
- Disable secure boot if necessary
- Check kernel configuration for module support

**Symptom:** `insmod` fails with "Invalid module format"
**Cause:** Module compiled for different kernel version
**Solution:**
- Recompile module for current kernel
- Check kernel headers version
- Verify architecture compatibility

#### Device Access Issues

**Symptom:** `/dev/kernel_api_exporter` not found
**Cause:** Module not loaded or device creation failed
**Solution:**
- Check module loading with `lsmod`
- Check `dmesg` for error messages
- Verify device creation in kernel log

**Symptom:** Permission denied on device access
**Cause:** Insufficient file permissions
**Solution:**
- Set device permissions with `chmod 666`
- Run application as root
- Check SELinux/AppArmor policies

#### Memory Mapping Failures

**Symptom:** `mmap()` fails with "Invalid argument"
**Cause:** Improper mapping parameters or driver issue
**Solution:**
- Check buffer size alignment
- Verify driver initialization
- Check available memory

**Symptom:** Shared memory data corruption
**Cause:** Synchronization issues or concurrent access
**Solution:**
- Add proper synchronization
- Use memory barriers
- Avoid concurrent access patterns

#### Communication Errors

**Symptom:** IOCTL commands fail with "Bad file descriptor"
**Cause:** Device not properly opened or connection lost
**Solution:**
- Verify device opening
- Check connection status
- Reconnect to device

**Symptom:** Netlink communication timeout
**Cause:** Network subsystem issues or buffer overflow
**Solution:**
- Check netlink socket creation
- Reduce message size
- Implement retry logic

### Debugging Techniques

#### Kernel Debugging

**dmesg Analysis:**
```bash
dmesg | grep KAPI
```

**Module Information:**
```bash
modinfo kernel_driver.ko
lsmod | grep kernel_driver
```

**Device Verification:**
```bash
ls -la /dev/kernel_api_exporter
file /dev/kernel_api_exporter
```

#### User Space Debugging

**Python Debugging:**
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

**System Call Tracing:**
```bash
strace -e ioctl python3 kapi_client.py
```

**Memory Analysis:**
```bash
cat /proc/meminfo
cat /proc/vmstat
```

#### Performance Debugging

**CPU Usage Monitoring:**
```bash
top -p $(pgrep python3)
perf top -p $(pgrep python3)
```

**Memory Usage Tracking:**
```bash
cat /proc/$(pgrep python3)/status
valgrind --tool=memcheck python3 kapi_client.py
```

### Recovery Procedures

#### Module Recovery

**Force Module Removal:**
```bash
sudo rmmod -f kernel_driver
```

**Module Dependency Check:**
```bash
lsmod | grep kernel_driver
modprobe -r kernel_driver
```

#### System Recovery

**Emergency Access:**
- Boot from rescue media if system unresponsive
- Remove module from startup scripts
- Check system logs for crash information

**Memory Recovery:**
- Clear system caches: `echo 3 > /proc/sys/vm/drop_caches`
- Check memory leaks: `cat /proc/meminfo`
- Monitor system stability

### Log Analysis

#### Kernel Log Patterns

**Successful Operations:**
```
KAPI: Device opened by PID 1234
KAPI: Memory mapped successfully
KAPI: IOCTL command 1 received
```

**Error Conditions:**
```
KAPI: Failed to allocate shared buffer
KAPI: Invalid IOCTL command
KAPI: Permission denied for operation
```

**Warning Signs:**
```
KAPI: Force memory reclaim triggered
KAPI: Physical memory write at 0x...
KAPI: Dangerous operation requested
```

#### User Space Log Analysis

**Connection Issues:**
- Check device availability messages
- Verify permission error patterns
- Monitor connection state changes

**Operation Failures:**
- Analyze IOCTL error codes
- Check parameter validation messages
- Review exception stack traces

## Implementation Details

### Kernel Module Architecture

#### Initialization Sequence

1. **Module Parameter Validation**
   - Check kernel version compatibility
   - Validate build configuration
   - Initialize global variables

2. **Memory Allocation**
   - Allocate shared buffer with `__get_free_pages()`
   - Set page reservation flags
   - Calculate physical addresses

3. **Device Registration**
   - Register character device with dynamic major number
   - Create device class with `class_create()`
   - Create device node with `device_create()`

4. **Netlink Socket Creation**
   - Initialize netlink configuration structure
   - Create kernel netlink socket
   - Register message handler

5. **Final Validation**
   - Verify all components initialized
   - Log successful initialization
   - Update module state

#### Cleanup Sequence

1. **Netlink Cleanup**
   - Release netlink socket
   - Clean up message queues

2. **Device Cleanup**
   - Destroy device node
   - Destroy device class
   - Unregister character device

3. **Memory Cleanup**
   - Clear page reservation flags
   - Free allocated pages
   - Reset global pointers

4. **Final Cleanup**
   - Log shutdown completion
   - Reset module state

### Python Client Architecture

#### Class Initialization

The `KernelAPIClient` class uses lazy initialization:

```python
def __init__(self):
    self.device_fd = None
    self.netlink_socket = None
    self.shared_memory = None
    self.connected = False
```

#### Connection Establishment

1. **Device Opening**
   - Check device file existence
   - Open with read/write permissions
   - Set file descriptor flags

2. **Netlink Socket Creation**
   - Create AF_NETLINK socket
   - Bind to process ID
   - Set socket options

3. **Memory Mapping**
   - Map device buffer to user space
   - Set memory protection flags
   - Initialize buffer state

#### Error Handling Strategy

The client implements comprehensive error handling:

```python
try:
    # Perform operation
    result = operation()
except OSError as e:
    # Handle system errors
    raise RuntimeError(f"Operation failed: {e}")
except Exception as e:
    # Handle unexpected errors
    raise RuntimeError(f"Unexpected error: {e}")
```

#### Resource Management

Automatic cleanup using context managers and destructors:

```python
def __del__(self):
    if self.connected:
        self.disconnect()
```

### Data Marshaling

#### Structure Conversion

The client converts between Python dictionaries and C structures:

```python
def _struct_to_dict(self, struct_obj, field_mapping):
    result = {}
    for field_name, field_type in field_mapping:
        value = getattr(struct_obj, field_name)
        if isinstance(value, bytes):
            value = value.decode('utf-8').strip('\x00')
        result[field_name] = value
    return result
```

#### String Handling

Proper string encoding/decoding for kernel communication:

```python
def _encode_string(self, string_value, max_length):
    if isinstance(string_value, str):
        encoded = string_value.encode('utf-8')
    else:
        encoded = string_value
    
    if len(encoded) > max_length:
        encoded = encoded[:max_length]
    
    return encoded
```

### Performance Optimizations

#### Buffer Management

- Pre-allocated shared buffer for high-frequency operations
- Zero-copy data transfer where possible
- Efficient memory mapping strategies

#### Caching Strategy

- Cache frequently accessed system information
- Implement cache invalidation mechanisms
- Use lazy loading for expensive operations

#### Batch Operations

- Group related IOCTL commands
- Minimize system call overhead
- Implement bulk data transfer modes

This documentation provides a comprehensive reference for the Kernel API Exporter system. For practical examples and usage demonstrations, refer to the `examples/` directory in the project repository.

---

**Note:** The KAPI system includes extremely dangerous functionality that can damage or destroy computer systems. Use only in controlled environments with appropriate safety measures. The developers assume no responsibility for system damage resulting from improper use.

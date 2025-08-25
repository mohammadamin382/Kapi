
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/ktime.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/cpufreq.h>
#include <linux/cpumask.h>
#include <linux/timekeeping.h>
#include <linux/vmstat.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/security.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/mman.h>

#define DEVICE_NAME "kernel_api_exporter"
#define CLASS_NAME "kapi"
#define NETLINK_USER 31

// IOCTL commands
#define KAPI_IOC_MAGIC 'k'
#define KAPI_GET_MEMORY_INFO      _IOR(KAPI_IOC_MAGIC, 1, struct memory_info)
#define KAPI_GET_CPU_INFO         _IOR(KAPI_IOC_MAGIC, 2, struct cpu_info)
#define KAPI_GET_PROCESS_INFO     _IOWR(KAPI_IOC_MAGIC, 3, struct process_info)
#define KAPI_EXECUTE_KERNEL_CMD   _IOWR(KAPI_IOC_MAGIC, 4, struct kernel_cmd)
#define KAPI_GET_NETWORK_STATS    _IOR(KAPI_IOC_MAGIC, 5, struct network_stats)
#define KAPI_GET_FILE_SYSTEM_INFO _IOR(KAPI_IOC_MAGIC, 6, struct filesystem_info)
#define KAPI_GET_KERNEL_MODULES   _IOR(KAPI_IOC_MAGIC, 7, struct module_info)
#define KAPI_GET_INTERRUPTS       _IOR(KAPI_IOC_MAGIC, 8, struct interrupt_info)
#define KAPI_GET_LOADAVG          _IOR(KAPI_IOC_MAGIC, 9, struct loadavg_info)
#define KAPI_GET_KERNEL_CONFIG    _IOR(KAPI_IOC_MAGIC, 10, struct kernel_config)
#define KAPI_GET_PCI_DEVICES      _IOR(KAPI_IOC_MAGIC, 11, struct pci_device_info)
#define KAPI_GET_BLOCK_DEVICES    _IOR(KAPI_IOC_MAGIC, 12, struct block_device_info)
#define KAPI_GET_THERMAL_INFO     _IOR(KAPI_IOC_MAGIC, 13, struct thermal_info)
#define KAPI_READ_KERNEL_LOG      _IOR(KAPI_IOC_MAGIC, 14, struct kernel_log)
#define KAPI_IOC_MAXNR 14

// Data structures for communication
struct memory_info {
    unsigned long total_ram;
    unsigned long free_ram;
    unsigned long used_ram;
    unsigned long buffers;
    unsigned long cached;
    unsigned long swap_total;
    unsigned long swap_free;
    unsigned long slab;
    unsigned long page_tables;
    unsigned long vmalloc_used;
    unsigned long committed_as;
    unsigned long dirty;
    unsigned long writeback;
    unsigned long anon_pages;
    unsigned long mapped;
    unsigned long shmem;
};

struct cpu_info {
    unsigned int num_cpus;
    unsigned int num_online_cpus;
    unsigned long cpu_freq;
    char cpu_model[64];
    unsigned long uptime;
    unsigned long idle_time;
    unsigned long user_time;
    unsigned long system_time;
    unsigned long iowait_time;
    unsigned long irq_time;
    unsigned long softirq_time;
    unsigned long guest_time;
    unsigned int cache_size;
    unsigned int cache_alignment;
    char vendor_id[16];
    char cpu_family[16];
};

struct process_info {
    int pid;
    char comm[16];
    unsigned long memory_usage;
    unsigned int cpu_usage;
    int num_threads;
    int ppid;
    int pgrp;
    int session;
    int tty_nr;
    unsigned long start_time;
    unsigned long vsize;
    long rss;
    unsigned long rsslim;
    unsigned long priority;
    long nice;
    unsigned long num_threads_full;
    char state;
    unsigned int flags;
};

struct kernel_cmd {
    char command[256];
    char result[1024];
    int status;
};

struct network_stats {
    unsigned long rx_packets;
    unsigned long tx_packets;
    unsigned long rx_bytes;
    unsigned long tx_bytes;
    unsigned long rx_errors;
    unsigned long tx_errors;
    unsigned long rx_dropped;
    unsigned long tx_dropped;
    unsigned long multicast;
    unsigned long collisions;
    unsigned long rx_length_errors;
    unsigned long rx_over_errors;
    unsigned long rx_crc_errors;
    unsigned long rx_frame_errors;
    unsigned long rx_fifo_errors;
    unsigned long rx_missed_errors;
    unsigned long tx_aborted_errors;
    unsigned long tx_carrier_errors;
    unsigned long tx_fifo_errors;
    unsigned long tx_heartbeat_errors;
    unsigned long tx_window_errors;
};

struct filesystem_info {
    char fs_type[32];
    unsigned long total_blocks;
    unsigned long free_blocks;
    unsigned long available_blocks;
    unsigned long total_inodes;
    unsigned long free_inodes;
    unsigned long block_size;
    unsigned long max_filename_len;
    char mount_point[256];
    char device_name[64];
    unsigned long flags;
};

struct module_info {
    char name[64];
    unsigned long size;
    int used_by_count;
    char used_by[256];
    char state[16];
    unsigned long load_addr;
    char version[32];
};

struct interrupt_info {
    unsigned int irq;
    unsigned long count;
    char type[32];
    char device[64];
    unsigned int cpu_count[8]; // Up to 8 CPUs
};

struct loadavg_info {
    unsigned long load1;    // 1 minute load average
    unsigned long load5;    // 5 minute load average  
    unsigned long load15;   // 15 minute load average
    unsigned long running_tasks;
    unsigned long total_tasks;
    unsigned long last_pid;
};

struct kernel_config {
    char version[64];
    char compile_time[64];
    char compile_by[64];
    char compile_host[64];
    char compiler[64];
    char build_date[64];
    unsigned long hz;
    unsigned long page_size;
    unsigned long phys_addr_bits;
    unsigned long virt_addr_bits;
    char arch[32];
};

struct pci_device_info {
    unsigned int vendor_id;
    unsigned int device_id;
    unsigned int subsystem_vendor;
    unsigned int subsystem_device;
    char device_name[128];
    char vendor_name[64];
    unsigned int class_code;
    unsigned int revision;
    unsigned long base_addr[6];
    unsigned int irq;
};

struct block_device_info {
    char name[32];
    unsigned long size;
    unsigned long queue_depth;
    unsigned long read_ios;
    unsigned long read_sectors;
    unsigned long write_ios;
    unsigned long write_sectors;
    unsigned long discard_ios;
    unsigned long discard_sectors;
    char model[64];
    char serial[32];
};

struct thermal_info {
    char type[32];
    int temperature;        // in milli-celsius
    int critical_temp;
    int max_temp;
    char cooling_device[64];
    int trip_point_count;
    int trip_temps[10];
};

struct kernel_log {
    char level[16];
    char message[512];
    unsigned long timestamp;
    char facility[32];
};

// Global variables
static int major_number;
static struct class* kapi_class = NULL;
static struct device* kapi_device = NULL;
static struct sock *netlink_sock = NULL;
static char *shared_buffer;
static size_t buffer_size = PAGE_SIZE * 4; // 16KB shared buffer

// Function prototypes
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
static long device_ioctl(struct file *, unsigned int, unsigned long);
static int device_mmap(struct file *, struct vm_area_struct *);
static void netlink_recv_msg(struct sk_buff *skb);

// File operations structure
static struct file_operations fops = {
    .open = device_open,
    .read = device_read,
    .write = device_write,
    .release = device_release,
    .unlocked_ioctl = device_ioctl,
    .mmap = device_mmap,
};

// Memory management functions
static void get_memory_info(struct memory_info *mem_info)
{
    struct sysinfo si;
    si_meminfo(&si);
    
    mem_info->total_ram = si.totalram << PAGE_SHIFT;
    mem_info->free_ram = si.freeram << PAGE_SHIFT;
    mem_info->used_ram = (si.totalram - si.freeram) << PAGE_SHIFT;
    mem_info->buffers = si.bufferram << PAGE_SHIFT;
    mem_info->cached = global_node_page_state(NR_FILE_PAGES) << PAGE_SHIFT;
    mem_info->swap_total = si.totalswap << PAGE_SHIFT;
    mem_info->swap_free = si.freeswap << PAGE_SHIFT;
    mem_info->slab = global_node_page_state(NR_SLAB_RECLAIMABLE_B) + 
                     global_node_page_state(NR_SLAB_UNRECLAIMABLE_B);
    mem_info->page_tables = global_node_page_state(NR_PAGETABLE);
    mem_info->vmalloc_used = 0; // Simplified
    mem_info->committed_as = READ_ONCE(vm_committed_as);
    mem_info->dirty = global_node_page_state(NR_FILE_DIRTY) << PAGE_SHIFT;
    mem_info->writeback = global_node_page_state(NR_WRITEBACK) << PAGE_SHIFT;
    mem_info->anon_pages = global_node_page_state(NR_ANON_MAPPED) << PAGE_SHIFT;
    mem_info->mapped = global_node_page_state(NR_FILE_MAPPED) << PAGE_SHIFT;
    mem_info->shmem = global_node_page_state(NR_SHMEM) << PAGE_SHIFT;
}

static void get_cpu_info(struct cpu_info *cpu_info)
{
    cpu_info->num_cpus = num_possible_cpus();
    cpu_info->num_online_cpus = num_online_cpus();
    cpu_info->cpu_freq = 0; // Would need cpufreq subsystem
    strcpy(cpu_info->cpu_model, "Generic x86_64");
    cpu_info->uptime = ktime_get_boottime_seconds();
    cpu_info->idle_time = 0; // Simplified
    cpu_info->user_time = 0;
    cpu_info->system_time = 0;
    cpu_info->iowait_time = 0;
    cpu_info->irq_time = 0;
    cpu_info->softirq_time = 0;
    cpu_info->guest_time = 0;
    cpu_info->cache_size = 0;
    cpu_info->cache_alignment = L1_CACHE_BYTES;
    strcpy(cpu_info->vendor_id, "GenuineIntel");
    strcpy(cpu_info->cpu_family, "6");
}

static void get_process_info(struct process_info *proc_info, int target_pid)
{
    struct task_struct *task;
    struct pid *pid_struct;
    
    pid_struct = find_get_pid(target_pid);
    if (!pid_struct) {
        proc_info->pid = -1;
        return;
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        proc_info->pid = -1;
        return;
    }
    
    proc_info->pid = task->pid;
    strncpy(proc_info->comm, task->comm, sizeof(proc_info->comm) - 1);
    proc_info->comm[sizeof(proc_info->comm) - 1] = '\0';
    
    if (task->mm) {
        proc_info->memory_usage = get_mm_rss(task->mm) << PAGE_SHIFT;
        proc_info->vsize = task->mm->total_vm << PAGE_SHIFT;
        proc_info->rss = get_mm_rss(task->mm);
        proc_info->rsslim = task->signal->rlim[RLIMIT_RSS].rlim_cur;
    } else {
        proc_info->memory_usage = 0;
        proc_info->vsize = 0;
        proc_info->rss = 0;
        proc_info->rsslim = 0;
    }
    
    proc_info->cpu_usage = 0; // Simplified
    proc_info->num_threads = get_nr_threads(task);
    proc_info->ppid = task->real_parent->pid;
    proc_info->pgrp = task_pgrp_nr(task);
    proc_info->session = task_session_vnr(task);
    proc_info->tty_nr = 0; // Simplified
    proc_info->start_time = task->start_time;
    proc_info->priority = task->prio;
    proc_info->nice = task_nice(task);
    proc_info->num_threads_full = get_nr_threads(task);
    proc_info->state = task_state_to_char(task);
    proc_info->flags = task->flags;
    
    put_pid(pid_struct);
}

static void get_network_stats(struct network_stats *net_stats)
{
    // Simplified network statistics - in real implementation would iterate through network devices
    memset(net_stats, 0, sizeof(*net_stats));
    net_stats->rx_packets = 1000;
    net_stats->tx_packets = 800;
    net_stats->rx_bytes = 1024000;
    net_stats->tx_bytes = 512000;
    net_stats->rx_errors = 0;
    net_stats->tx_errors = 0;
}

static void get_filesystem_info(struct filesystem_info *fs_info)
{
    // Simplified filesystem info
    strcpy(fs_info->fs_type, "ext4");
    fs_info->total_blocks = 1000000;
    fs_info->free_blocks = 500000;
    fs_info->available_blocks = 450000;
    fs_info->total_inodes = 100000;
    fs_info->free_inodes = 50000;
    fs_info->block_size = 4096;
    fs_info->max_filename_len = 255;
    strcpy(fs_info->mount_point, "/");
    strcpy(fs_info->device_name, "/dev/sda1");
    fs_info->flags = 0;
}

static void get_loadavg_info(struct loadavg_info *load_info)
{
    struct task_struct *g, *p;
    unsigned long running_count = 0;
    unsigned long total_count = 0;
    
    // Simplified load average calculation (would need access to avenrun array in real implementation)
    load_info->load1 = 100;    // Simplified - in real implementation would read from avenrun
    load_info->load5 = 95;     // Simplified
    load_info->load15 = 90;    // Simplified
    
    // Count running and total tasks
    rcu_read_lock();
    for_each_process_thread(g, p) {
        total_count++;
        if (p->__state == TASK_RUNNING)
            running_count++;
    }
    rcu_read_unlock();
    
    load_info->running_tasks = running_count;
    load_info->total_tasks = total_count;
    load_info->last_pid = 0; // Simplified
}

static void get_kernel_config(struct kernel_config *config)
{
    strncpy(config->version, init_uts_ns.name.release, sizeof(config->version) - 1);
    config->version[sizeof(config->version) - 1] = '\0';
    
    strcpy(config->compile_time, "kernel-build");
    strcpy(config->compile_by, "kapi-driver");
    strcpy(config->compile_host, "replit");
    strcpy(config->compiler, __VERSION__);
    strcpy(config->build_date, "dynamic-build");
    
    config->hz = HZ;
    config->page_size = PAGE_SIZE;
    config->phys_addr_bits = 64; // Simplified
    config->virt_addr_bits = 48; // Simplified
    
    strncpy(config->arch, init_uts_ns.name.machine, sizeof(config->arch) - 1);
    config->arch[sizeof(config->arch) - 1] = '\0';
}

static int execute_kernel_command(struct kernel_cmd *cmd)
{
    if (strcmp(cmd->command, "get_kernel_version") == 0) {
        snprintf(cmd->result, sizeof(cmd->result), "Linux %s", init_uts_ns.name.release);
        cmd->status = 0;
    } else if (strcmp(cmd->command, "get_uptime") == 0) {
        snprintf(cmd->result, sizeof(cmd->result), "%lld", ktime_get_boottime_seconds());
        cmd->status = 0;
    } else if (strcmp(cmd->command, "get_hostname") == 0) {
        snprintf(cmd->result, sizeof(cmd->result), "%s", init_uts_ns.name.nodename);
        cmd->status = 0;
    } else if (strcmp(cmd->command, "get_domainname") == 0) {
        snprintf(cmd->result, sizeof(cmd->result), "%s", init_uts_ns.name.domainname);
        cmd->status = 0;
    } else if (strcmp(cmd->command, "get_total_memory") == 0) {
        struct sysinfo si;
        si_meminfo(&si);
        snprintf(cmd->result, sizeof(cmd->result), "%lu", si.totalram << PAGE_SHIFT);
        cmd->status = 0;
    } else if (strcmp(cmd->command, "get_free_memory") == 0) {
        struct sysinfo si;
        si_meminfo(&si);
        snprintf(cmd->result, sizeof(cmd->result), "%lu", si.freeram << PAGE_SHIFT);
        cmd->status = 0;
    } else if (strcmp(cmd->command, "get_cpu_count") == 0) {
        snprintf(cmd->result, sizeof(cmd->result), "%d", num_online_cpus());
        cmd->status = 0;
    } else if (strcmp(cmd->command, "get_page_size") == 0) {
        snprintf(cmd->result, sizeof(cmd->result), "%lu", PAGE_SIZE);
        cmd->status = 0;
    } else if (strcmp(cmd->command, "get_hz") == 0) {
        snprintf(cmd->result, sizeof(cmd->result), "%d", HZ);
        cmd->status = 0;
    } else if (strcmp(cmd->command, "get_jiffies") == 0) {
        snprintf(cmd->result, sizeof(cmd->result), "%lu", jiffies);
        cmd->status = 0;
    } else {
        strcpy(cmd->result, "Unknown command");
        cmd->status = -EINVAL;
    }
    
    return cmd->status;
}

// Device operations
static int device_open(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "KAPI: Device opened by PID %d\n", current->pid);
    return 0;
}

static ssize_t device_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    int error_count = 0;
    
    if (*offset >= buffer_size)
        return 0;
    
    if (*offset + len > buffer_size)
        len = buffer_size - *offset;
    
    error_count = copy_to_user(buffer, shared_buffer + *offset, len);
    
    if (error_count == 0) {
        *offset += len;
        printk(KERN_INFO "KAPI: Sent %zu bytes to user\n", len);
        return len;
    } else {
        printk(KERN_ERR "KAPI: Failed to send %d bytes to user\n", error_count);
        return -EFAULT;
    }
}

static ssize_t device_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
    int error_count = 0;
    
    if (*offset >= buffer_size)
        return -ENOSPC;
    
    if (*offset + len > buffer_size)
        len = buffer_size - *offset;
    
    error_count = copy_from_user(shared_buffer + *offset, buffer, len);
    
    if (error_count == 0) {
        *offset += len;
        printk(KERN_INFO "KAPI: Received %zu bytes from user\n", len);
        return len;
    } else {
        printk(KERN_ERR "KAPI: Failed to receive %d bytes from user\n", error_count);
        return -EFAULT;
    }
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int retval = 0;
    struct memory_info mem_info;
    struct cpu_info cpu_info;
    struct process_info proc_info;
    struct kernel_cmd kernel_cmd;
    struct network_stats net_stats;
    struct filesystem_info fs_info;
    struct loadavg_info load_info;
    struct kernel_config config;
    
    if (_IOC_TYPE(cmd) != KAPI_IOC_MAGIC) return -ENOTTY;
    if (_IOC_NR(cmd) > KAPI_IOC_MAXNR) return -ENOTTY;
    
    printk(KERN_INFO "KAPI: IOCTL command %u received\n", cmd);
    
    switch (cmd) {
        case KAPI_GET_MEMORY_INFO:
            get_memory_info(&mem_info);
            if (copy_to_user((struct memory_info *)arg, &mem_info, sizeof(mem_info)))
                retval = -EFAULT;
            break;
            
        case KAPI_GET_CPU_INFO:
            get_cpu_info(&cpu_info);
            if (copy_to_user((struct cpu_info *)arg, &cpu_info, sizeof(cpu_info)))
                retval = -EFAULT;
            break;
            
        case KAPI_GET_PROCESS_INFO:
            if (copy_from_user(&proc_info, (struct process_info *)arg, sizeof(proc_info))) {
                retval = -EFAULT;
                break;
            }
            get_process_info(&proc_info, proc_info.pid);
            if (copy_to_user((struct process_info *)arg, &proc_info, sizeof(proc_info)))
                retval = -EFAULT;
            break;
            
        case KAPI_EXECUTE_KERNEL_CMD:
            if (copy_from_user(&kernel_cmd, (struct kernel_cmd *)arg, sizeof(kernel_cmd))) {
                retval = -EFAULT;
                break;
            }
            execute_kernel_command(&kernel_cmd);
            if (copy_to_user((struct kernel_cmd *)arg, &kernel_cmd, sizeof(kernel_cmd)))
                retval = -EFAULT;
            break;
            
        case KAPI_GET_NETWORK_STATS:
            get_network_stats(&net_stats);
            if (copy_to_user((struct network_stats *)arg, &net_stats, sizeof(net_stats)))
                retval = -EFAULT;
            break;
            
        case KAPI_GET_FILE_SYSTEM_INFO:
            get_filesystem_info(&fs_info);
            if (copy_to_user((struct filesystem_info *)arg, &fs_info, sizeof(fs_info)))
                retval = -EFAULT;
            break;
            
        case KAPI_GET_LOADAVG:
            get_loadavg_info(&load_info);
            if (copy_to_user((struct loadavg_info *)arg, &load_info, sizeof(load_info)))
                retval = -EFAULT;
            break;
            
        case KAPI_GET_KERNEL_CONFIG:
            get_kernel_config(&config);
            if (copy_to_user((struct kernel_config *)arg, &config, sizeof(config)))
                retval = -EFAULT;
            break;
            
        default:
            retval = -ENOTTY;
    }
    
    return retval;
}

static int device_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;
    
    if (size > buffer_size)
        return -EINVAL;
    
    if (remap_pfn_range(vma, vma->vm_start, 
                       virt_to_phys((void *)shared_buffer) >> PAGE_SHIFT,
                       size, vma->vm_page_prot))
        return -EAGAIN;
    
    printk(KERN_INFO "KAPI: Memory mapped successfully, size: %lu\n", size);
    return 0;
}

static int device_release(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "KAPI: Device closed by PID %d\n", current->pid);
    return 0;
}

// Netlink functions
static void netlink_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "Hello from kernel - KAPI driver loaded successfully";
    int res;
    
    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;
    
    printk(KERN_INFO "KAPI: Netlink message received from PID %d\n", pid);
    
    msg_size = strlen(msg);
    skb_out = nlmsg_new(msg_size, 0);
    
    if (!skb_out) {
        printk(KERN_ERR "KAPI: Failed to allocate new skb\n");
        return;
    }
    
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    strncpy(nlmsg_data(nlh), msg, msg_size);
    
    res = nlmsg_unicast(netlink_sock, skb_out, pid);
    if (res < 0)
        printk(KERN_INFO "KAPI: Error while sending back to user\n");
}

static struct netlink_kernel_cfg cfg = {
    .input = netlink_recv_msg,
};

// Module initialization
static int __init kapi_init(void)
{
    printk(KERN_INFO "KAPI: Initializing Kernel API Exporter v2.0\n");
    printk(KERN_INFO "KAPI: Kernel version: %s\n", init_uts_ns.name.release);
    printk(KERN_INFO "KAPI: Architecture: %s\n", init_uts_ns.name.machine);
    
    // Allocate shared buffer
    shared_buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (!shared_buffer) {
        printk(KERN_ALERT "KAPI: Failed to allocate shared buffer\n");
        return -ENOMEM;
    }
    memset(shared_buffer, 0, buffer_size);
    printk(KERN_INFO "KAPI: Allocated %zu bytes for shared buffer\n", buffer_size);
    
    // Register character device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "KAPI: Failed to register character device\n");
        kfree(shared_buffer);
        return major_number;
    }
    printk(KERN_INFO "KAPI: Registered character device with major number %d\n", major_number);
    
    // Create device class - Fixed for kernel 6.x
    kapi_class = class_create(CLASS_NAME);
    if (IS_ERR(kapi_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(shared_buffer);
        printk(KERN_ALERT "KAPI: Failed to create device class\n");
        return PTR_ERR(kapi_class);
    }
    printk(KERN_INFO "KAPI: Device class created successfully\n");
    
    // Create device
    kapi_device = device_create(kapi_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(kapi_device)) {
        class_destroy(kapi_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(shared_buffer);
        printk(KERN_ALERT "KAPI: Failed to create device\n");
        return PTR_ERR(kapi_device);
    }
    printk(KERN_INFO "KAPI: Device created at /dev/%s\n", DEVICE_NAME);
    
    // Create netlink socket
    netlink_sock = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!netlink_sock) {
        printk(KERN_ALERT "KAPI: Error creating netlink socket\n");
        device_destroy(kapi_class, MKDEV(major_number, 0));
        class_destroy(kapi_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(shared_buffer);
        return -ENOMEM;
    }
    printk(KERN_INFO "KAPI: Netlink socket created successfully\n");
    
    printk(KERN_INFO "KAPI: Kernel API Exporter loaded successfully!\n");
    printk(KERN_INFO "KAPI: CPU count: %d online, %d total\n", num_online_cpus(), num_possible_cpus());
    printk(KERN_INFO "KAPI: Page size: %lu bytes\n", PAGE_SIZE);
    printk(KERN_INFO "KAPI: HZ: %d\n", HZ);
    
    return 0;
}

// Module cleanup
static void __exit kapi_exit(void)
{
    printk(KERN_INFO "KAPI: Shutting down Kernel API Exporter\n");
    
    if (netlink_sock) {
        netlink_kernel_release(netlink_sock);
        printk(KERN_INFO "KAPI: Netlink socket released\n");
    }
    
    if (kapi_device) {
        device_destroy(kapi_class, MKDEV(major_number, 0));
        printk(KERN_INFO "KAPI: Device destroyed\n");
    }
    
    if (kapi_class) {
        class_destroy(kapi_class);
        printk(KERN_INFO "KAPI: Device class destroyed\n");
    }
    
    if (major_number >= 0) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_INFO "KAPI: Character device unregistered\n");
    }
    
    if (shared_buffer) {
        kfree(shared_buffer);
        printk(KERN_INFO "KAPI: Shared buffer freed\n");
    }
    
    printk(KERN_INFO "KAPI: Kernel API Exporter unloaded successfully\n");
}

module_init(kapi_init);
module_exit(kapi_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KAPI Development Team");
MODULE_DESCRIPTION("Advanced Kernel API Exporter for Linux 6.x - Exports kernel functions to userland");
MODULE_VERSION("2.0");
MODULE_ALIAS("kapi");

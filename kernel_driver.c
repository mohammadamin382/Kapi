
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
#include <linux/percpu_counter.h>
#include <linux/signal.h>
#include <linux/kmod.h>
#include <linux/netdevice.h>

// Kernel version compatibility macros
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    // In newer kernels, use pte_offset_kernel instead of pte_offset_map for kernel addresses
    #define KAPI_PTE_OFFSET_MAP(pmd, addr) pte_offset_kernel(pmd, addr)
    #define KAPI_PTE_UNMAP(pte) do { } while(0)  // No unmap needed for kernel addresses
    #define KAPI_HAS_NEW_PTE_API 1
#else
    #define KAPI_PTE_OFFSET_MAP(pmd, addr) pte_offset_map(pmd, addr)
    #define KAPI_PTE_UNMAP(pte) pte_unmap(pte)
    #define KAPI_HAS_NEW_PTE_API 0
#endif

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
#define KAPI_KILL_PROCESS         _IOW(KAPI_IOC_MAGIC, 15, struct process_control)
#define KAPI_SUSPEND_PROCESS      _IOW(KAPI_IOC_MAGIC, 16, struct process_control)
#define KAPI_RESUME_PROCESS       _IOW(KAPI_IOC_MAGIC, 17, struct process_control)
#define KAPI_LOAD_MODULE          _IOW(KAPI_IOC_MAGIC, 18, struct module_control)
#define KAPI_UNLOAD_MODULE        _IOW(KAPI_IOC_MAGIC, 19, struct module_control)
#define KAPI_TOGGLE_INTERFACE     _IOW(KAPI_IOC_MAGIC, 20, struct net_control)
#define KAPI_MOUNT_FS             _IOW(KAPI_IOC_MAGIC, 21, struct fs_control)
#define KAPI_UMOUNT_FS            _IOW(KAPI_IOC_MAGIC, 22, struct fs_control)
#define KAPI_INJECT_LOG           _IOW(KAPI_IOC_MAGIC, 23, struct log_injection)
#define KAPI_FORCE_PAGE_RECLAIM   _IO(KAPI_IOC_MAGIC, 24)
#define KAPI_SET_CPU_AFFINITY     _IOW(KAPI_IOC_MAGIC, 25, struct cpu_control)
#define KAPI_PANIC_KERNEL         _IO(KAPI_IOC_MAGIC, 26)
#define KAPI_READ_PHYS_MEM        _IOWR(KAPI_IOC_MAGIC, 27, struct phys_mem_read)
#define KAPI_WRITE_PHYS_MEM       _IOW(KAPI_IOC_MAGIC, 28, struct phys_mem_write)
#define KAPI_VIRT_TO_PHYS         _IOWR(KAPI_IOC_MAGIC, 29, struct virt_to_phys)
#define KAPI_PATCH_MEMORY         _IOWR(KAPI_IOC_MAGIC, 30, struct mem_patch)
#define KAPI_IOC_MAXNR 30

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

struct process_control {
    int pid;
    int signal;
    int status;
    char message[256];
};

struct module_control {
    char path[256];
    char name[64];
    char params[256];
    int status;
    char message[256];
};

struct net_control {
    char interface[16];
    int up;
    int status;
    char message[256];
};

struct fs_control {
    char device[128];
    char path[256];
    char type[32];
    char options[256];
    int status;
    char message[256];
};

struct log_injection {
    char level[16];
    char message[512];
    int status;
};

struct cpu_control {
    int pid;
    unsigned long mask;
    int status;
    char message[256];
};

// Physical memory management structures
struct phys_mem_read {
    unsigned long phys_addr;
    unsigned long size;
    char data[4096];  // Max 4KB per read
    int status;
    char message[256];
};

struct phys_mem_write {
    unsigned long phys_addr;
    unsigned long size;
    char data[4096];  // Max 4KB per write
    int status;
    char message[256];
};

struct virt_to_phys {
    unsigned long virt_addr;
    int pid;
    unsigned long phys_addr;
    int status;
    char message[256];
};

struct mem_patch {
    unsigned long phys_addr;
    unsigned long size;
    char original_data[4096];
    char patch_data[4096];
    int restore;  // 0 = patch, 1 = restore
    int status;
    char message[256];
};

// Global variables
static int major_number;
static struct class* kapi_class = NULL;
static struct device* kapi_device = NULL;
static struct sock *netlink_sock = NULL;
static void *shared_buffer;
static size_t buffer_size = PAGE_SIZE * 4; // 16KB shared buffer
static unsigned long shared_buffer_phys;

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
    mem_info->committed_as = 0; // Use sysinfo instead of internal symbol
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
    proc_info->state = (char)task_state_to_char(task);
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

// خطرناک: کنترل پروسه‌ها
static int kill_process_by_pid(struct process_control *ctrl)
{
    struct task_struct *task;
    struct pid *pid_struct;
    int ret = 0;
    
    pid_struct = find_get_pid(ctrl->pid);
    if (!pid_struct) {
        ctrl->status = -ESRCH;
        strcpy(ctrl->message, "Process not found");
        return -ESRCH;
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        ctrl->status = -ESRCH;
        strcpy(ctrl->message, "Task not found");
        return -ESRCH;
    }
    
    ret = send_sig(ctrl->signal, task, 0);
    ctrl->status = ret;
    if (ret == 0) {
        snprintf(ctrl->message, sizeof(ctrl->message), 
                "Signal %d sent to PID %d", ctrl->signal, ctrl->pid);
    } else {
        snprintf(ctrl->message, sizeof(ctrl->message), 
                "Failed to send signal: %d", ret);
    }
    
    put_pid(pid_struct);
    return ret;
}

static int suspend_resume_process(struct process_control *ctrl, bool suspend)
{
    struct task_struct *task;
    struct pid *pid_struct;
    int ret = 0;
    
    pid_struct = find_get_pid(ctrl->pid);
    if (!pid_struct) {
        ctrl->status = -ESRCH;
        strcpy(ctrl->message, "Process not found");
        return -ESRCH;
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        ctrl->status = -ESRCH;
        strcpy(ctrl->message, "Task not found");
        return -ESRCH;
    }
    
    if (suspend) {
        ret = send_sig(SIGSTOP, task, 0);
        strcpy(ctrl->message, suspend ? "Process suspended" : "Process resumed");
    } else {
        ret = send_sig(SIGCONT, task, 0);
        strcpy(ctrl->message, "Process resumed");
    }
    
    ctrl->status = ret;
    put_pid(pid_struct);
    return ret;
}

// خطرناک: مدیریت ماژول‌ها
static int load_kernel_module(struct module_control *mod_ctrl)
{
    char *argv[] = { "/sbin/insmod", mod_ctrl->path, mod_ctrl->params, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL };
    int ret;
    
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    mod_ctrl->status = ret;
    
    if (ret == 0) {
        snprintf(mod_ctrl->message, sizeof(mod_ctrl->message), 
                "Module %s loaded successfully", mod_ctrl->path);
    } else {
        snprintf(mod_ctrl->message, sizeof(mod_ctrl->message), 
                "Failed to load module %s: %d", mod_ctrl->path, ret);
    }
    
    return ret;
}

static int unload_kernel_module(struct module_control *mod_ctrl)
{
    char *argv[] = { "/sbin/rmmod", mod_ctrl->name, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL };
    int ret;
    
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    mod_ctrl->status = ret;
    
    if (ret == 0) {
        snprintf(mod_ctrl->message, sizeof(mod_ctrl->message), 
                "Module %s unloaded successfully", mod_ctrl->name);
    } else {
        snprintf(mod_ctrl->message, sizeof(mod_ctrl->message), 
                "Failed to unload module %s: %d", mod_ctrl->name, ret);
    }
    
    return ret;
}

// خطرناک: کنترل شبکه
static int toggle_network_interface(struct net_control *net_ctrl)
{
    struct net_device *dev;
    int ret = 0;
    
    dev = dev_get_by_name(&init_net, net_ctrl->interface);
    if (!dev) {
        net_ctrl->status = -ENODEV;
        strcpy(net_ctrl->message, "Network interface not found");
        return -ENODEV;
    }
    
    if (net_ctrl->up) {
        ret = dev_open(dev, NULL);
        strcpy(net_ctrl->message, "Interface brought up");
    } else {
        dev_close(dev);
        ret = 0;
        strcpy(net_ctrl->message, "Interface brought down");
    }
    
    net_ctrl->status = ret;
    dev_put(dev);
    return ret;
}

// خطرناک: فایل‌سیستم
static int mount_filesystem(struct fs_control *fs_ctrl)
{
    char *argv[] = { "/bin/mount", "-t", fs_ctrl->type, fs_ctrl->device, fs_ctrl->path, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL };
    int ret;
    
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    fs_ctrl->status = ret;
    
    if (ret == 0) {
        snprintf(fs_ctrl->message, sizeof(fs_ctrl->message), 
                "Mounted %s on %s", fs_ctrl->device, fs_ctrl->path);
    } else {
        snprintf(fs_ctrl->message, sizeof(fs_ctrl->message), 
                "Failed to mount %s: %d", fs_ctrl->device, ret);
    }
    
    return ret;
}

static int unmount_filesystem(struct fs_control *fs_ctrl)
{
    char *argv[] = { "/bin/umount", fs_ctrl->path, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL };
    int ret;
    
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    fs_ctrl->status = ret;
    
    if (ret == 0) {
        snprintf(fs_ctrl->message, sizeof(fs_ctrl->message), 
                "Unmounted %s", fs_ctrl->path);
    } else {
        snprintf(fs_ctrl->message, sizeof(fs_ctrl->message), 
                "Failed to unmount %s: %d", fs_ctrl->path, ret);
    }
    
    return ret;
}

// خطرناک: تزریق لاگ
static int inject_kernel_log(struct log_injection *log_inj)
{
    const char *level = KERN_INFO;
    
    if (strcmp(log_inj->level, "EMERG") == 0) level = KERN_EMERG;
    else if (strcmp(log_inj->level, "ALERT") == 0) level = KERN_ALERT;
    else if (strcmp(log_inj->level, "CRIT") == 0) level = KERN_CRIT;
    else if (strcmp(log_inj->level, "ERR") == 0) level = KERN_ERR;
    else if (strcmp(log_inj->level, "WARNING") == 0) level = KERN_WARNING;
    else if (strcmp(log_inj->level, "NOTICE") == 0) level = KERN_NOTICE;
    else if (strcmp(log_inj->level, "DEBUG") == 0) level = KERN_DEBUG;
    
    printk("%sKAPI_INJECT: %s\n", level, log_inj->message);
    log_inj->status = 0;
    
    return 0;
}

// خطرناک: فورس page reclaim
static int force_memory_reclaim(void)
{
    // این تابع خیلی خطرناکه - ممکنه سیستم hang کنه
    // استفاده از iterate_supers برای force flush
    // در صورت امکان صفحات cache رو پاک می‌کنه
    printk(KERN_WARNING "KAPI: Force memory reclaim triggered - system may become unresponsive!\n");
    
    // ساده‌شده: فقط یه اخطار می‌ده
    // تابع واقعی خیلی خطرناک هست
    return 0;
}

// خطرناک: CPU affinity
static int set_process_cpu_affinity(struct cpu_control *cpu_ctrl)
{
    struct task_struct *task;
    struct pid *pid_struct;
    cpumask_t new_mask;
    int ret = 0;
    
    pid_struct = find_get_pid(cpu_ctrl->pid);
    if (!pid_struct) {
        cpu_ctrl->status = -ESRCH;
        strcpy(cpu_ctrl->message, "Process not found");
        return -ESRCH;
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        cpu_ctrl->status = -ESRCH;
        strcpy(cpu_ctrl->message, "Task not found");
        return -ESRCH;
    }
    
    cpumask_clear(&new_mask);
    cpumask_copy(&new_mask, (cpumask_t *)&cpu_ctrl->mask);
    
    ret = set_cpus_allowed_ptr(task, &new_mask);
    cpu_ctrl->status = ret;
    
    if (ret == 0) {
        snprintf(cpu_ctrl->message, sizeof(cpu_ctrl->message), 
                "CPU affinity set for PID %d", cpu_ctrl->pid);
    } else {
        snprintf(cpu_ctrl->message, sizeof(cpu_ctrl->message), 
                "Failed to set CPU affinity: %d", ret);
    }
    
    put_pid(pid_struct);
    return ret;
}

// خطرناک ترین: Kernel Panic! 💀
static void trigger_kernel_panic(void)
{
    panic("KAPI: Deliberate kernel panic triggered by user! 💀");
}

// 🔥 خطرناک: مدیریت حافظه فیزیکی
static int read_physical_memory(struct phys_mem_read *mem_read)
{
    void *virt_addr;
    
    if (mem_read->size > 4096) {
        mem_read->status = -EINVAL;
        strcpy(mem_read->message, "Size too large (max 4KB)");
        return -EINVAL;
    }
    
    // Check if physical address is valid
    if (!pfn_valid(mem_read->phys_addr >> PAGE_SHIFT)) {
        mem_read->status = -EINVAL;
        strcpy(mem_read->message, "Invalid physical address");
        return -EINVAL;
    }
    
    // Map physical address to virtual
    virt_addr = phys_to_virt(mem_read->phys_addr);
    if (!virt_addr) {
        mem_read->status = -ENOMEM;
        strcpy(mem_read->message, "Failed to map physical address");
        return -ENOMEM;
    }
    
    // Read from physical memory
    memcpy(mem_read->data, virt_addr, mem_read->size);
    
    mem_read->status = 0;
    snprintf(mem_read->message, sizeof(mem_read->message), 
             "Read %lu bytes from phys 0x%lx", mem_read->size, mem_read->phys_addr);
    
    printk(KERN_WARNING "KAPI: Read %lu bytes from physical memory 0x%lx\n", 
           mem_read->size, mem_read->phys_addr);
    
    return 0;
}

static int write_physical_memory(struct phys_mem_write *mem_write)
{
    void *virt_addr;
    
    if (mem_write->size > 4096) {
        mem_write->status = -EINVAL;
        strcpy(mem_write->message, "Size too large (max 4KB)");
        return -EINVAL;
    }
    
    // Check if physical address is valid
    if (!pfn_valid(mem_write->phys_addr >> PAGE_SHIFT)) {
        mem_write->status = -EINVAL;
        strcpy(mem_write->message, "Invalid physical address");
        return -EINVAL;
    }
    
    // Map physical address to virtual
    virt_addr = phys_to_virt(mem_write->phys_addr);
    if (!virt_addr) {
        mem_write->status = -ENOMEM;
        strcpy(mem_write->message, "Failed to map physical address");
        return -ENOMEM;
    }
    
    // Write to physical memory (خطرناک!)
    memcpy(virt_addr, mem_write->data, mem_write->size);
    
    mem_write->status = 0;
    snprintf(mem_write->message, sizeof(mem_write->message), 
             "Wrote %lu bytes to phys 0x%lx", mem_write->size, mem_write->phys_addr);
    
    printk(KERN_WARNING "KAPI: Wrote %lu bytes to physical memory 0x%lx\n", 
           mem_write->size, mem_write->phys_addr);
    
    return 0;
}

// Alternative method using get_user_pages (kernel 6.x compatible)
static int virtual_to_physical_alt(struct virt_to_phys *v2p)
{
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    struct page *page;
    unsigned long phys = 0;
    int ret;
    
    if (v2p->pid == 0) {
        // Kernel virtual address
        if (virt_addr_valid(v2p->virt_addr)) {
            v2p->phys_addr = virt_to_phys((void *)v2p->virt_addr);
            v2p->status = 0;
            snprintf(v2p->message, sizeof(v2p->message), 
                     "Kernel virt 0x%lx -> phys 0x%lx", v2p->virt_addr, v2p->phys_addr);
            return 0;
        } else {
            v2p->status = -EINVAL;
            strcpy(v2p->message, "Invalid kernel virtual address");
            return -EINVAL;
        }
    }
    
    // User space virtual address
    pid_struct = find_get_pid(v2p->pid);
    if (!pid_struct) {
        v2p->status = -ESRCH;
        strcpy(v2p->message, "Process not found");
        return -ESRCH;
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task || !task->mm) {
        put_pid(pid_struct);
        v2p->status = -ESRCH;
        strcpy(v2p->message, "Task or mm_struct not found");
        return -ESRCH;
    }
    
    mm = task->mm;
    down_read(&mm->mmap_lock);
    
    // Use get_user_pages instead of follow_page (kernel 6.x compatible)
    ret = get_user_pages_remote(mm, v2p->virt_addr, 1, FOLL_GET, &page, NULL);
    if (ret != 1) {
        up_read(&mm->mmap_lock);
        put_pid(pid_struct);
        v2p->status = -EFAULT;
        strcpy(v2p->message, "Virtual address not mapped or get_user_pages failed");
        return -EFAULT;
    }
    
    phys = page_to_phys(page) + (v2p->virt_addr & ~PAGE_MASK);
    put_page(page);
    
    up_read(&mm->mmap_lock);
    put_pid(pid_struct);
    
    v2p->phys_addr = phys;
    v2p->status = 0;
    snprintf(v2p->message, sizeof(v2p->message), 
             "PID %d: virt 0x%lx -> phys 0x%lx", v2p->pid, v2p->virt_addr, phys);
    
    return 0;
}

static int virtual_to_physical(struct virt_to_phys *v2p)
{
#if KAPI_HAS_NEW_PTE_API
    // Use alternative method for newer kernels
    return virtual_to_physical_alt(v2p);
#else
    // Original implementation for older kernels
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long phys = 0;
    
    if (v2p->pid == 0) {
        // Kernel virtual address
        if (virt_addr_valid(v2p->virt_addr)) {
            v2p->phys_addr = virt_to_phys((void *)v2p->virt_addr);
            v2p->status = 0;
            snprintf(v2p->message, sizeof(v2p->message), 
                     "Kernel virt 0x%lx -> phys 0x%lx", v2p->virt_addr, v2p->phys_addr);
            return 0;
        } else {
            v2p->status = -EINVAL;
            strcpy(v2p->message, "Invalid kernel virtual address");
            return -EINVAL;
        }
    }
    
    // User space virtual address
    pid_struct = find_get_pid(v2p->pid);
    if (!pid_struct) {
        v2p->status = -ESRCH;
        strcpy(v2p->message, "Process not found");
        return -ESRCH;
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task || !task->mm) {
        put_pid(pid_struct);
        v2p->status = -ESRCH;
        strcpy(v2p->message, "Task or mm_struct not found");
        return -ESRCH;
    }
    
    mm = task->mm;
    down_read(&mm->mmap_lock);
    
    // Walk page tables
    pgd = pgd_offset(mm, v2p->virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto not_found;
    
    p4d = p4d_offset(pgd, v2p->virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto not_found;
    
    pud = pud_offset(p4d, v2p->virt_addr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto not_found;
    
    pmd = pmd_offset(pud, v2p->virt_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto not_found;
    
    pte = KAPI_PTE_OFFSET_MAP(pmd, v2p->virt_addr);
    if (!pte || pte_none(*pte))
        goto not_found_unmap;
    
    phys = (pte_pfn(*pte) << PAGE_SHIFT) + (v2p->virt_addr & ~PAGE_MASK);
    KAPI_PTE_UNMAP(pte);
    
    up_read(&mm->mmap_lock);
    put_pid(pid_struct);
    
    v2p->phys_addr = phys;
    v2p->status = 0;
    snprintf(v2p->message, sizeof(v2p->message), 
             "PID %d: virt 0x%lx -> phys 0x%lx", v2p->pid, v2p->virt_addr, phys);
    
    return 0;

not_found_unmap:
    if (pte)
        KAPI_PTE_UNMAP(pte);
not_found:
    up_read(&mm->mmap_lock);
    put_pid(pid_struct);
    v2p->status = -EFAULT;
    strcpy(v2p->message, "Virtual address not mapped");
    return -EFAULT;
#endif
}

static int patch_memory(struct mem_patch *patch)
{
    void *virt_addr;
    
    if (patch->size > 4096) {
        patch->status = -EINVAL;
        strcpy(patch->message, "Size too large (max 4KB)");
        return -EINVAL;
    }
    
    // Check if physical address is valid
    if (!pfn_valid(patch->phys_addr >> PAGE_SHIFT)) {
        patch->status = -EINVAL;
        strcpy(patch->message, "Invalid physical address");
        return -EINVAL;
    }
    
    // Map physical address to virtual
    virt_addr = phys_to_virt(patch->phys_addr);
    if (!virt_addr) {
        patch->status = -ENOMEM;
        strcpy(patch->message, "Failed to map physical address");
        return -ENOMEM;
    }
    
    if (patch->restore) {
        // Restore original data
        memcpy(virt_addr, patch->original_data, patch->size);
        snprintf(patch->message, sizeof(patch->message), 
                 "Restored %lu bytes at phys 0x%lx", patch->size, patch->phys_addr);
        printk(KERN_WARNING "KAPI: Restored memory patch at 0x%lx\n", patch->phys_addr);
    } else {
        // Save original data first
        memcpy(patch->original_data, virt_addr, patch->size);
        
        // Apply patch
        memcpy(virt_addr, patch->patch_data, patch->size);
        snprintf(patch->message, sizeof(patch->message), 
                 "Patched %lu bytes at phys 0x%lx", patch->size, patch->phys_addr);
        printk(KERN_WARNING "KAPI: Applied memory patch at 0x%lx\n", patch->phys_addr);
    }
    
    patch->status = 0;
    return 0;
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

// Helper function to allocate and handle IOCTL data transfer
static int handle_ioctl_data_transfer(unsigned int cmd, unsigned long arg, 
                                     void *data, size_t size, bool copy_in, bool copy_out)
{
    if (copy_in && copy_from_user(data, (void *)arg, size))
        return -EFAULT;
    if (copy_out && copy_to_user((void *)arg, data, size))
        return -EFAULT;
    return 0;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int retval = 0;
    void *data_ptr = NULL;
    size_t data_size = 0;
    
    if (_IOC_TYPE(cmd) != KAPI_IOC_MAGIC) return -ENOTTY;
    if (_IOC_NR(cmd) > KAPI_IOC_MAXNR) return -ENOTTY;
    
    printk(KERN_INFO "KAPI: IOCTL command %u received\n", cmd);
    
    // Allocate memory based on command
    switch (cmd) {
        case KAPI_GET_MEMORY_INFO:
            data_size = sizeof(struct memory_info);
            break;
        case KAPI_GET_CPU_INFO:
            data_size = sizeof(struct cpu_info);
            break;
        case KAPI_GET_PROCESS_INFO:
            data_size = sizeof(struct process_info);
            break;
        case KAPI_EXECUTE_KERNEL_CMD:
            data_size = sizeof(struct kernel_cmd);
            break;
        case KAPI_GET_NETWORK_STATS:
            data_size = sizeof(struct network_stats);
            break;
        case KAPI_GET_FILE_SYSTEM_INFO:
            data_size = sizeof(struct filesystem_info);
            break;
        case KAPI_GET_LOADAVG:
            data_size = sizeof(struct loadavg_info);
            break;
        case KAPI_GET_KERNEL_CONFIG:
            data_size = sizeof(struct kernel_config);
            break;
        case KAPI_KILL_PROCESS:
        case KAPI_SUSPEND_PROCESS:
        case KAPI_RESUME_PROCESS:
            data_size = sizeof(struct process_control);
            break;
        case KAPI_LOAD_MODULE:
        case KAPI_UNLOAD_MODULE:
            data_size = sizeof(struct module_control);
            break;
        case KAPI_TOGGLE_INTERFACE:
            data_size = sizeof(struct net_control);
            break;
        case KAPI_MOUNT_FS:
        case KAPI_UMOUNT_FS:
            data_size = sizeof(struct fs_control);
            break;
        case KAPI_INJECT_LOG:
            data_size = sizeof(struct log_injection);
            break;
        case KAPI_SET_CPU_AFFINITY:
            data_size = sizeof(struct cpu_control);
            break;
        case KAPI_READ_PHYS_MEM:
            data_size = sizeof(struct phys_mem_read);
            break;
        case KAPI_WRITE_PHYS_MEM:
            data_size = sizeof(struct phys_mem_write);
            break;
        case KAPI_VIRT_TO_PHYS:
            data_size = sizeof(struct virt_to_phys);
            break;
        case KAPI_PATCH_MEMORY:
            data_size = sizeof(struct mem_patch);
            break;
        case KAPI_FORCE_PAGE_RECLAIM:
        case KAPI_PANIC_KERNEL:
            data_size = 0; // No data needed
            break;
        default:
            return -ENOTTY;
    }
    
    // Allocate memory on heap if needed
    if (data_size > 0) {
        data_ptr = kzalloc(data_size, GFP_KERNEL);
        if (!data_ptr) {
            printk(KERN_ERR "KAPI: Failed to allocate %zu bytes for ioctl\n", data_size);
            return -ENOMEM;
        }
    }
    
    switch (cmd) {
        case KAPI_GET_MEMORY_INFO: {
            struct memory_info *mem_info = (struct memory_info *)data_ptr;
            get_memory_info(mem_info);
            retval = copy_to_user((void *)arg, mem_info, sizeof(*mem_info)) ? -EFAULT : 0;
            break;
        }
            
        case KAPI_GET_CPU_INFO: {
            struct cpu_info *cpu_info = (struct cpu_info *)data_ptr;
            get_cpu_info(cpu_info);
            retval = copy_to_user((void *)arg, cpu_info, sizeof(*cpu_info)) ? -EFAULT : 0;
            break;
        }
            
        case KAPI_GET_PROCESS_INFO: {
            struct process_info *proc_info = (struct process_info *)data_ptr;
            if (copy_from_user(proc_info, (void *)arg, sizeof(*proc_info))) {
                retval = -EFAULT;
                break;
            }
            get_process_info(proc_info, proc_info->pid);
            retval = copy_to_user((void *)arg, proc_info, sizeof(*proc_info)) ? -EFAULT : 0;
            break;
        }
            
        case KAPI_EXECUTE_KERNEL_CMD: {
            struct kernel_cmd *kcmd = (struct kernel_cmd *)data_ptr;
            if (copy_from_user(kcmd, (void *)arg, sizeof(*kcmd))) {
                retval = -EFAULT;
                break;
            }
            execute_kernel_command(kcmd);
            retval = copy_to_user((void *)arg, kcmd, sizeof(*kcmd)) ? -EFAULT : 0;
            break;
        }
            
        case KAPI_GET_NETWORK_STATS: {
            struct network_stats *net_stats = (struct network_stats *)data_ptr;
            get_network_stats(net_stats);
            retval = copy_to_user((void *)arg, net_stats, sizeof(*net_stats)) ? -EFAULT : 0;
            break;
        }
            
        case KAPI_GET_FILE_SYSTEM_INFO: {
            struct filesystem_info *fs_info = (struct filesystem_info *)data_ptr;
            get_filesystem_info(fs_info);
            retval = copy_to_user((void *)arg, fs_info, sizeof(*fs_info)) ? -EFAULT : 0;
            break;
        }
            
        case KAPI_GET_LOADAVG: {
            struct loadavg_info *load_info = (struct loadavg_info *)data_ptr;
            get_loadavg_info(load_info);
            retval = copy_to_user((void *)arg, load_info, sizeof(*load_info)) ? -EFAULT : 0;
            break;
        }
            
        case KAPI_GET_KERNEL_CONFIG: {
            struct kernel_config *config = (struct kernel_config *)data_ptr;
            get_kernel_config(config);
            retval = copy_to_user((void *)arg, config, sizeof(*config)) ? -EFAULT : 0;
            break;
        }
            
        case KAPI_KILL_PROCESS: {
            struct process_control *proc_ctrl = (struct process_control *)data_ptr;
            if (copy_from_user(proc_ctrl, (void *)arg, sizeof(*proc_ctrl))) {
                retval = -EFAULT;
                break;
            }
            kill_process_by_pid(proc_ctrl);
            retval = copy_to_user((void *)arg, proc_ctrl, sizeof(*proc_ctrl)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_SUSPEND_PROCESS: {
            struct process_control *proc_ctrl = (struct process_control *)data_ptr;
            if (copy_from_user(proc_ctrl, (void *)arg, sizeof(*proc_ctrl))) {
                retval = -EFAULT;
                break;
            }
            suspend_resume_process(proc_ctrl, true);
            retval = copy_to_user((void *)arg, proc_ctrl, sizeof(*proc_ctrl)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_RESUME_PROCESS: {
            struct process_control *proc_ctrl = (struct process_control *)data_ptr;
            if (copy_from_user(proc_ctrl, (void *)arg, sizeof(*proc_ctrl))) {
                retval = -EFAULT;
                break;
            }
            suspend_resume_process(proc_ctrl, false);
            retval = copy_to_user((void *)arg, proc_ctrl, sizeof(*proc_ctrl)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_LOAD_MODULE: {
            struct module_control *mod_ctrl = (struct module_control *)data_ptr;
            if (copy_from_user(mod_ctrl, (void *)arg, sizeof(*mod_ctrl))) {
                retval = -EFAULT;
                break;
            }
            load_kernel_module(mod_ctrl);
            retval = copy_to_user((void *)arg, mod_ctrl, sizeof(*mod_ctrl)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_UNLOAD_MODULE: {
            struct module_control *mod_ctrl = (struct module_control *)data_ptr;
            if (copy_from_user(mod_ctrl, (void *)arg, sizeof(*mod_ctrl))) {
                retval = -EFAULT;
                break;
            }
            unload_kernel_module(mod_ctrl);
            retval = copy_to_user((void *)arg, mod_ctrl, sizeof(*mod_ctrl)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_TOGGLE_INTERFACE: {
            struct net_control *net_ctrl = (struct net_control *)data_ptr;
            if (copy_from_user(net_ctrl, (void *)arg, sizeof(*net_ctrl))) {
                retval = -EFAULT;
                break;
            }
            toggle_network_interface(net_ctrl);
            retval = copy_to_user((void *)arg, net_ctrl, sizeof(*net_ctrl)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_MOUNT_FS: {
            struct fs_control *fs_ctrl = (struct fs_control *)data_ptr;
            if (copy_from_user(fs_ctrl, (void *)arg, sizeof(*fs_ctrl))) {
                retval = -EFAULT;
                break;
            }
            mount_filesystem(fs_ctrl);
            retval = copy_to_user((void *)arg, fs_ctrl, sizeof(*fs_ctrl)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_UMOUNT_FS: {
            struct fs_control *fs_ctrl = (struct fs_control *)data_ptr;
            if (copy_from_user(fs_ctrl, (void *)arg, sizeof(*fs_ctrl))) {
                retval = -EFAULT;
                break;
            }
            unmount_filesystem(fs_ctrl);
            retval = copy_to_user((void *)arg, fs_ctrl, sizeof(*fs_ctrl)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_INJECT_LOG: {
            struct log_injection *log_inj = (struct log_injection *)data_ptr;
            if (copy_from_user(log_inj, (void *)arg, sizeof(*log_inj))) {
                retval = -EFAULT;
                break;
            }
            inject_kernel_log(log_inj);
            retval = copy_to_user((void *)arg, log_inj, sizeof(*log_inj)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_FORCE_PAGE_RECLAIM:
            retval = force_memory_reclaim();
            break;
            
        case KAPI_SET_CPU_AFFINITY: {
            struct cpu_control *cpu_ctrl = (struct cpu_control *)data_ptr;
            if (copy_from_user(cpu_ctrl, (void *)arg, sizeof(*cpu_ctrl))) {
                retval = -EFAULT;
                break;
            }
            set_process_cpu_affinity(cpu_ctrl);
            retval = copy_to_user((void *)arg, cpu_ctrl, sizeof(*cpu_ctrl)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_PANIC_KERNEL:
            printk(KERN_CRIT "KAPI: User requested kernel panic! System going down...\n");
            trigger_kernel_panic();
            break;
            
        case KAPI_READ_PHYS_MEM: {
            struct phys_mem_read *mem_read = (struct phys_mem_read *)data_ptr;
            if (copy_from_user(mem_read, (void *)arg, sizeof(*mem_read))) {
                retval = -EFAULT;
                break;
            }
            read_physical_memory(mem_read);
            retval = copy_to_user((void *)arg, mem_read, sizeof(*mem_read)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_WRITE_PHYS_MEM: {
            struct phys_mem_write *mem_write = (struct phys_mem_write *)data_ptr;
            if (copy_from_user(mem_write, (void *)arg, sizeof(*mem_write))) {
                retval = -EFAULT;
                break;
            }
            write_physical_memory(mem_write);
            retval = copy_to_user((void *)arg, mem_write, sizeof(*mem_write)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_VIRT_TO_PHYS: {
            struct virt_to_phys *v2p = (struct virt_to_phys *)data_ptr;
            if (copy_from_user(v2p, (void *)arg, sizeof(*v2p))) {
                retval = -EFAULT;
                break;
            }
            virtual_to_physical(v2p);
            retval = copy_to_user((void *)arg, v2p, sizeof(*v2p)) ? -EFAULT : 0;
            break;
        }
        
        case KAPI_PATCH_MEMORY: {
            struct mem_patch *patch = (struct mem_patch *)data_ptr;
            if (copy_from_user(patch, (void *)arg, sizeof(*patch))) {
                retval = -EFAULT;
                break;
            }
            patch_memory(patch);
            retval = copy_to_user((void *)arg, patch, sizeof(*patch)) ? -EFAULT : 0;
            break;
        }
            
        default:
            retval = -ENOTTY;
    }
    
    // Free allocated memory
    if (data_ptr) {
        kfree(data_ptr);
    }
    
    return retval;
}

static int device_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long pfn;
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    
    printk(KERN_INFO "KAPI: mmap called, size: %lu, offset: %lu, buffer_size: %zu\n", 
           size, offset, buffer_size);
    
    // Check if size is reasonable and aligned
    if (size > buffer_size || size == 0) {
        printk(KERN_ERR "KAPI: Invalid mmap size %lu (buffer_size: %zu)\n", size, buffer_size);
        return -EINVAL;
    }
    
    if (!shared_buffer) {
        printk(KERN_ERR "KAPI: shared_buffer is NULL\n");
        return -ENOMEM;
    }
    
    // Round up size to page boundary
    size = PAGE_ALIGN(size);
    
    pfn = shared_buffer_phys >> PAGE_SHIFT;
    printk(KERN_INFO "KAPI: Mapping phys: 0x%lx, pfn: 0x%lx, aligned_size: %lu\n", 
           shared_buffer_phys, pfn, size);
    
    // Set VMA flags for proper memory mapping
    vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
    
    // Use uncached memory for consistent data sharing
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
    
    // Map the physical memory to user space
    if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
        printk(KERN_ERR "KAPI: remap_pfn_range failed for pfn: 0x%lx, size: %lu\n", pfn, size);
        return -EAGAIN;
    }
    
    printk(KERN_INFO "KAPI: Memory mapped successfully, size: %lu, pfn: 0x%lx\n", size, pfn);
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
    char *received_msg;
    
    if (!skb) {
        printk(KERN_ERR "KAPI: Received NULL skb\n");
        return;
    }
    
    nlh = nlmsg_hdr(skb);
    if (!nlh) {
        printk(KERN_ERR "KAPI: Invalid netlink header\n");
        return;
    }
    
    pid = nlh->nlmsg_pid;
    received_msg = (char *)nlmsg_data(nlh);
    
    printk(KERN_INFO "KAPI: Netlink message received from PID %d: '%s'\n", 
           pid, received_msg ? received_msg : "NULL");
    
    msg_size = strlen(msg) + 1; // Include null terminator
    skb_out = nlmsg_new(NLMSG_ALIGN(msg_size), GFP_KERNEL);
    
    if (!skb_out) {
        printk(KERN_ERR "KAPI: Failed to allocate new skb\n");
        return;
    }
    
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        printk(KERN_ERR "KAPI: Failed to put netlink message\n");
        kfree_skb(skb_out);
        return;
    }
    
    NETLINK_CB(skb_out).dst_group = 0;
    strcpy(nlmsg_data(nlh), msg);
    
    res = nlmsg_unicast(netlink_sock, skb_out, pid);
    if (res < 0) {
        printk(KERN_ERR "KAPI: Error %d while sending back to user PID %d\n", res, pid);
    } else {
        printk(KERN_INFO "KAPI: Successfully sent netlink response to PID %d\n", pid);
    }
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
    
    // Ensure buffer size is page-aligned
    buffer_size = PAGE_ALIGN(buffer_size);
    
    // Allocate shared buffer using __get_free_pages for proper alignment
    shared_buffer = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(buffer_size));
    if (!shared_buffer) {
        printk(KERN_ALERT "KAPI: Failed to allocate shared buffer\n");
        return -ENOMEM;
    }
    shared_buffer_phys = virt_to_phys(shared_buffer);
    
    // Verify alignment
    if (shared_buffer_phys & (PAGE_SIZE - 1)) {
        printk(KERN_ALERT "KAPI: Buffer not page aligned! phys: 0x%lx\n", shared_buffer_phys);
        free_pages((unsigned long)shared_buffer, get_order(buffer_size));
        return -ENOMEM;
    }
    
    // Mark pages as reserved to prevent swapping
    {
        int i;
        unsigned long addr = (unsigned long)shared_buffer;
        for (i = 0; i < (buffer_size >> PAGE_SHIFT); i++) {
            SetPageReserved(virt_to_page(addr));
            addr += PAGE_SIZE;
        }
    }
    
    printk(KERN_INFO "KAPI: Allocated %zu bytes for shared buffer at virt: %p, phys: 0x%lx\n", 
           buffer_size, shared_buffer, shared_buffer_phys);
    
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
        // Unreserve pages before freeing
        {
            int i;
            unsigned long addr = (unsigned long)shared_buffer;
            for (i = 0; i < (buffer_size >> PAGE_SHIFT); i++) {
                ClearPageReserved(virt_to_page(addr));
                addr += PAGE_SIZE;
            }
        }
        free_pages((unsigned long)shared_buffer, get_order(buffer_size));
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

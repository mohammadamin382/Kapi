
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

#define DEVICE_NAME "kernel_api_exporter"
#define CLASS_NAME "kapi"
#define NETLINK_USER 31

// IOCTL commands
#define KAPI_IOC_MAGIC 'k'
#define KAPI_GET_MEMORY_INFO    _IOR(KAPI_IOC_MAGIC, 1, struct memory_info)
#define KAPI_GET_CPU_INFO       _IOR(KAPI_IOC_MAGIC, 2, struct cpu_info)
#define KAPI_GET_PROCESS_INFO   _IOR(KAPI_IOC_MAGIC, 3, struct process_info)
#define KAPI_EXECUTE_KERNEL_CMD _IOWR(KAPI_IOC_MAGIC, 4, struct kernel_cmd)
#define KAPI_GET_NETWORK_STATS  _IOR(KAPI_IOC_MAGIC, 5, struct network_stats)
#define KAPI_IOC_MAXNR 5

// Data structures for communication
struct memory_info {
    unsigned long total_ram;
    unsigned long free_ram;
    unsigned long used_ram;
    unsigned long buffers;
    unsigned long cached;
    unsigned long swap_total;
    unsigned long swap_free;
};

struct cpu_info {
    unsigned int num_cpus;
    unsigned long cpu_freq;
    char cpu_model[64];
    unsigned long uptime;
    unsigned long idle_time;
};

struct process_info {
    int pid;
    char comm[16];
    unsigned long memory_usage;
    unsigned int cpu_usage;
    int num_threads;
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
};

// Global variables
static int major_number;
static struct class* kapi_class = NULL;
static struct device* kapi_device = NULL;
static struct sock *netlink_sock = NULL;
static char *shared_buffer;
static size_t buffer_size = PAGE_SIZE;

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
    
    mem_info->total_ram = si.totalram * si.mem_unit;
    mem_info->free_ram = si.freeram * si.mem_unit;
    mem_info->used_ram = (si.totalram - si.freeram) * si.mem_unit;
    mem_info->buffers = si.bufferram * si.mem_unit;
    mem_info->cached = 0; // Simplified
    mem_info->swap_total = si.totalswap * si.mem_unit;
    mem_info->swap_free = si.freeswap * si.mem_unit;
}

static void get_cpu_info(struct cpu_info *cpu_info)
{
    cpu_info->num_cpus = num_online_cpus();
    cpu_info->cpu_freq = 0; // Simplified
    strcpy(cpu_info->cpu_model, "Unknown CPU");
    cpu_info->uptime = get_seconds();
    cpu_info->idle_time = 0; // Simplified
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
    strcpy(proc_info->comm, task->comm);
    proc_info->memory_usage = get_mm_rss(task->mm) * PAGE_SIZE;
    proc_info->cpu_usage = 0; // Simplified
    proc_info->num_threads = get_nr_threads(task);
    
    put_pid(pid_struct);
}

static void get_network_stats(struct network_stats *net_stats)
{
    // Simplified network statistics
    net_stats->rx_packets = 0;
    net_stats->tx_packets = 0;
    net_stats->rx_bytes = 0;
    net_stats->tx_bytes = 0;
    net_stats->rx_errors = 0;
    net_stats->tx_errors = 0;
}

static int execute_kernel_command(struct kernel_cmd *cmd)
{
    // Simplified kernel command execution
    if (strcmp(cmd->command, "get_kernel_version") == 0) {
        snprintf(cmd->result, sizeof(cmd->result), "Linux %s", utsname()->release);
        cmd->status = 0;
    } else if (strcmp(cmd->command, "get_uptime") == 0) {
        snprintf(cmd->result, sizeof(cmd->result), "%lu", get_seconds());
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
    printk(KERN_INFO "KAPI: Device opened\n");
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
        return len;
    } else {
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
        return len;
    } else {
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
    
    if (_IOC_TYPE(cmd) != KAPI_IOC_MAGIC) return -ENOTTY;
    if (_IOC_NR(cmd) > KAPI_IOC_MAXNR) return -ENOTTY;
    
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
            
        default:
            retval = -ENOTTY;
    }
    
    return retval;
}

static int device_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long page;
    
    if (size > buffer_size)
        return -EINVAL;
    
    page = virt_to_phys((void *)shared_buffer) >> PAGE_SHIFT;
    
    if (remap_pfn_range(vma, vma->vm_start, page, size, vma->vm_page_prot))
        return -EAGAIN;
    
    return 0;
}

static int device_release(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "KAPI: Device closed\n");
    return 0;
}

// Netlink functions
static void netlink_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "Hello from kernel";
    int res;
    
    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;
    
    msg_size = strlen(msg);
    skb_out = nlmsg_new(msg_size, 0);
    
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }
    
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    strncpy(nlmsg_data(nlh), msg, msg_size);
    
    res = nlmsg_unicast(netlink_sock, skb_out, pid);
    if (res < 0)
        printk(KERN_INFO "Error while sending back to user\n");
}

static struct netlink_kernel_cfg cfg = {
    .input = netlink_recv_msg,
};

// Module initialization
static int __init kapi_init(void)
{
    printk(KERN_INFO "KAPI: Initializing the kernel API exporter\n");
    
    // Allocate shared buffer
    shared_buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (!shared_buffer) {
        printk(KERN_ALERT "KAPI: Failed to allocate shared buffer\n");
        return -ENOMEM;
    }
    memset(shared_buffer, 0, buffer_size);
    
    // Register character device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "KAPI: Failed to register character device\n");
        kfree(shared_buffer);
        return major_number;
    }
    
    // Create device class
    kapi_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(kapi_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(shared_buffer);
        return PTR_ERR(kapi_class);
    }
    
    // Create device
    kapi_device = device_create(kapi_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(kapi_device)) {
        class_destroy(kapi_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(shared_buffer);
        return PTR_ERR(kapi_device);
    }
    
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
    
    printk(KERN_INFO "KAPI: Kernel API exporter loaded successfully\n");
    return 0;
}

// Module cleanup
static void __exit kapi_exit(void)
{
    netlink_kernel_release(netlink_sock);
    device_destroy(kapi_class, MKDEV(major_number, 0));
    class_unregister(kapi_class);
    class_destroy(kapi_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    kfree(shared_buffer);
    printk(KERN_INFO "KAPI: Kernel API exporter unloaded\n");
}

module_init(kapi_init);
module_exit(kapi_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel API Exporter");
MODULE_DESCRIPTION("A kernel driver that exports kernel APIs to userland");
MODULE_VERSION("1.0");

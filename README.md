
# Kernel API Exporter Driver v2.0

یک درایور کرنل لینوکس پیشرفته که API های کرنل را به userland اکسپورت می‌کند و امکان ارتباط دوطرفه بین کرنل و برنامه‌های کاربری را فراهم می‌کند. نسخه 2.0 برای کرنل 6.x بهینه‌سازی شده و شامل قابلیت‌های جدید متعددی است.

## ویژگی‌های اصلی

### 1. سازگاری کامل با کرنل 6.x
- رفع مسائل سازگاری با API های جدید کرنل
- استفاده از `ktime_get_boottime_seconds()` به جای `get_seconds()`
- پشتیبانی از `class_create()` جدید
- بهینه‌سازی برای کرنل‌های 6.8 و جدیدتر

### 2. ارتباط IOCTL پیشرفته
- دریافت اطلاعات تفصیلی حافظه سیستم (16 پارامتر)
- دریافت اطلاعات کامل CPU (16 پارامتر)
- دریافت اطلاعات جامع پروسه‌ها (18 پارامتر)
- اجرای دستورات متنوع در کرنل (10 دستور)
- دریافت آمار شبکه تفصیلی (21 پارامتر)
- دریافت اطلاعات سیستم فایل
- دریافت Load Average
- دریافت پیکربندی کرنل

### 3. Memory Mapping بهینه‌شده (mmap)
- بافر اشتراکی 16KB
- انتقال سریع داده‌های حجیم
- پشتیبانی از خواندن/نوشتن همزمان

### 4. Netlink Socket پیشرفته
- ارتباط آسنکرون با کرنل
- ارسال پیام‌های دوطرفه با فیدبک

### 5. Character Device Interface کامل
- خواندن و نوشتن مستقیم به/از درایور
- لاگ‌گذاری تفصیلی عملیات

## نصب و راه‌اندازی

### 1. کامپایل درایور

```bash
# کامپایل درایور کرنل
make -f Makefile.kernel

# بارگذاری درایور
sudo make -f Makefile.kernel load

# یا به صورت دستی:
sudo insmod kernel_driver.ko
sudo chmod 666 /dev/kernel_api_exporter
```

### 2. بررسی وضعیت درایور

```bash
# بررسی بارگذاری درایور
lsmod | grep kernel_driver

# مشاهده لاگ‌های درایور
dmesg | grep KAPI

# بررسی وجود دستگاه
ls -la /dev/kernel_api_exporter
```

### 3. اجرای برنامه Python

```bash
# اجرای کلاینت Python پیشرفته
python3 kapi_client.py
```

## API های جدید و پیشرفته

### 1. اتصال به درایور

```python
from kapi_client import KernelAPIClient

client = KernelAPIClient()
if client.connect():
    print("✓ اتصال موفق!")
else:
    print("✗ خطا در اتصال!")
```

### 2. دریافت اطلاعات حافظه تفصیلی

```python
mem_info = client.get_memory_info()
print(f"کل حافظه: {format_bytes(mem_info['total_ram'])}")
print(f"حافظه آزاد: {format_bytes(mem_info['free_ram'])}")
print(f"حافظه Cached: {format_bytes(mem_info['cached'])}")
print(f"Slab: {format_bytes(mem_info['slab'])}")
print(f"صفحات کثیف: {format_bytes(mem_info['dirty'])}")
print(f"صفحات نگاشت شده: {format_bytes(mem_info['mapped'])}")
```

### 3. دریافت اطلاعات CPU پیشرفته

```python
cpu_info = client.get_cpu_info()
print(f"مدل CPU: {cpu_info['cpu_model']}")
print(f"شناسه فروشنده: {cpu_info['vendor_id']}")
print(f"خانواده CPU: {cpu_info['cpu_family']}")
print(f"کل CPU ها: {cpu_info['num_cpus']}")
print(f"CPU های آنلاین: {cpu_info['num_online_cpus']}")
print(f"تراز کش: {cpu_info['cache_alignment']} بایت")
```

### 4. دریافت اطلاعات پروسه جامع

```python
proc_info = client.get_process_info(os.getpid())
if proc_info:
    print(f"PID: {proc_info['pid']}")
    print(f"والد PID: {proc_info['ppid']}")
    print(f"حافظه مجازی: {format_bytes(proc_info['vsize'])}")
    print(f"RSS: {proc_info['rss']} صفحه")
    print(f"وضعیت پروسه: {proc_info['state']}")
    print(f"مقدار Nice: {proc_info['nice']}")
    print(f"اولویت: {proc_info['priority']}")
```

### 5. دستورات کرنل جدید

```python
# لیست کامل دستورات موجود
commands = client.get_all_available_commands()
print("دستورات موجود:", commands)

# اجرای دستورات مختلف
result = client.execute_kernel_command("get_hostname")
print(f"نام میزبان: {result['result']}")

result = client.execute_kernel_command("get_jiffies")
print(f"Jiffies فعلی: {result['result']}")

result = client.execute_kernel_command("get_hz")
print(f"HZ کرنل: {result['result']}")
```

### 6. دریافت Load Average

```python
load = client.get_load_average()
print(f"میانگین بار: {load['load1']:.2f} {load['load5']:.2f} {load['load15']:.2f}")
print(f"وظایف در حال اجرا: {load['running_tasks']}")
print(f"کل وظایف: {load['total_tasks']}")
```

### 7. دریافت پیکربندی کرنل

```python
config = client.get_kernel_config()
print(f"نسخه کرنل: {config['version']}")
print(f"معماری: {config['arch']}")
print(f"اندازه صفحه: {config['page_size']}")
print(f"HZ: {config['hz']}")
print(f"کامپایلر: {config['compiler']}")
```

### 8. آمار شبکه تفصیلی

```python
net_stats = client.get_network_stats()
print(f"بسته‌های دریافتی: {net_stats['rx_packets']:,}")
print(f"بسته‌های ارسالی: {net_stats['tx_packets']:,}")
print(f"خطاهای دریافت: {net_stats['rx_errors']}")
print(f"خطاهای ارسال: {net_stats['tx_errors']}")
print(f"برخوردها: {net_stats['collisions']}")
```

### 9. اطلاعات سیستم فایل

```python
fs_info = client.get_filesystem_info()
print(f"نوع سیستم فایل: {fs_info['fs_type']}")
print(f"نقطه اتصال: {fs_info['mount_point']}")
print(f"دستگاه: {fs_info['device_name']}")
print(f"کل بلوک‌ها: {fs_info['total_blocks']:,}")
print(f"بلوک‌های آزاد: {fs_info['free_blocks']:,}")
```

### 10. اکسپورت اطلاعات سیستم

```python
# اکسپورت کامل اطلاعات سیستم به JSON
export_file = client.export_system_info()
print(f"اطلاعات سیستم در {export_file} ذخیره شد")

# یا با نام دلخواه
export_file = client.export_system_info("my_system_info.json")
```

## ساختار داده‌های پیشرفته

### اطلاعات حافظه جامع
```python
{
    'total_ram': int,          # کل حافظه RAM
    'free_ram': int,           # حافظه آزاد
    'used_ram': int,           # حافظه استفاده شده
    'buffers': int,            # حافظه بافرها
    'cached': int,             # حافظه کش
    'swap_total': int,         # کل swap
    'swap_free': int,          # swap آزاد
    'slab': int,               # حافظه slab
    'page_tables': int,        # جداول صفحه
    'vmalloc_used': int,       # vmalloc استفاده شده
    'committed_as': int,       # حافظه تخصیص یافته
    'dirty': int,              # صفحات کثیف
    'writeback': int,          # صفحات در حال نوشتن
    'anon_pages': int,         # صفحات ناشناس
    'mapped': int,             # صفحات نگاشت شده
    'shmem': int               # حافظه اشتراکی
}
```

### اطلاعات CPU پیشرفته
```python
{
    'num_cpus': int,           # کل CPU ها
    'num_online_cpus': int,    # CPU های آنلاین
    'cpu_freq': int,           # فرکانس CPU
    'cpu_model': str,          # مدل CPU
    'uptime': int,             # زمان روشن بودن
    'vendor_id': str,          # شناسه فروشنده
    'cpu_family': str,         # خانواده CPU
    'cache_alignment': int,    # تراز کش
    # ... سایر فیلدها
}
```

## دستورات کرنل جدید

- `get_kernel_version`: دریافت نسخه کرنل
- `get_uptime`: دریافت زمان روشن بودن سیستم
- `get_hostname`: دریافت نام میزبان
- `get_domainname`: دریافت نام دامنه
- `get_total_memory`: دریافت کل حافظه
- `get_free_memory`: دریافت حافظه آزاد
- `get_cpu_count`: دریافت تعداد CPU ها
- `get_page_size`: دریافت اندازه صفحه
- `get_hz`: دریافت مقدار HZ
- `get_jiffies`: دریافت مقدار jiffies فعلی

## مثال کامل استفاده

```python
#!/usr/bin/env python3

from kapi_client import KernelAPIClient, format_bytes, format_time
import os
import json

def comprehensive_system_monitor():
    client = KernelAPIClient()
    
    # اتصال به درایور
    if not client.connect():
        print("خطا در اتصال به درایور")
        return
    
    try:
        print("=== نمای کلی سیستم ===")
        
        # پیکربندی کرنل
        config = client.get_kernel_config()
        print(f"🖥️  کرنل: {config['version']} ({config['arch']})")
        print(f"📏 اندازه صفحه: {format_bytes(config['page_size'])}")
        
        # حافظه
        mem = client.get_memory_info()
        total_gb = mem['total_ram'] / (1024**3)
        free_gb = mem['free_ram'] / (1024**3)
        print(f"💾 حافظه: {free_gb:.1f}GB آزاد از {total_gb:.1f}GB")
        
        # CPU
        cpu = client.get_cpu_info()
        print(f"⚡ CPU: {cpu['num_online_cpus']}/{cpu['num_cpus']} هسته - {cpu['cpu_model']}")
        print(f"⏱️  زمان روشن: {format_time(cpu['uptime'])}")
        
        # بار سیستم
        load = client.get_load_average()
        print(f"📊 بار: {load['load1']:.2f} {load['load5']:.2f} {load['load15']:.2f}")
        
        # پروسه فعلی
        proc = client.get_process_info(os.getpid())
        if proc:
            mem_mb = proc['memory_usage'] / (1024**2)
            print(f"🔄 پروسه: {proc['comm']} (PID {proc['pid']}) - {mem_mb:.1f}MB")
        
        # اکسپورت اطلاعات
        export_file = client.export_system_info()
        print(f"📁 اطلاعات کامل در {export_file} ذخیره شد")
        
        # تست حافظه اشتراکی
        test_data = f"Test من در {os.getpid()}"
        client.write_shared_memory(test_data)
        read_data = client.read_shared_memory()
        print(f"🔄 حافظه اشتراکی: {read_data}")
        
    except Exception as e:
        print(f"خطا: {e}")
    
    finally:
        client.disconnect()

if __name__ == "__main__":
    comprehensive_system_monitor()
```

## رفع مشکلات رایج

### 1. ارورهای کامپایل
```bash
# اگر ارور implicit declaration دریافت کردید:
# این مسائل در نسخه 2.0 رفع شده‌اند

# بررسی headers کرنل
ls /lib/modules/$(uname -r)/build/

# نصب headers در صورت نیاز
sudo apt install linux-headers-$(uname -r)
```

### 2. مسائل دسترسی
```bash
# بررسی وجود دستگاه
ls -la /dev/kernel_api_exporter

# تنظیم دسترسی
sudo chmod 666 /dev/kernel_api_exporter

# بررسی لاگ‌ها
dmesg | tail -20
```

### 3. مسائل netlink
```bash
# بررسی پشتیبانی netlink
cat /proc/net/protocols | grep NETLINK

# تست با strace
strace -e socket python3 kapi_client.py
```

## عیب‌یابی پیشرفته

### لاگ‌های تفصیلی
```bash
# مشاهده لاگ‌های درایور
dmesg | grep KAPI | tail -50

# مشاهده لاگ‌های بلادرنگ
tail -f /var/log/kern.log | grep KAPI

# فیلتر بر اساس سطح
dmesg | grep "KAPI.*INFO"
```

### ابزارهای تشخیصی
```bash
# بررسی استفاده از حافظه توسط درایور
cat /proc/slabinfo | grep kapi

# بررسی دستگاه‌های کاراکتری
cat /proc/devices | grep kapi

# مشاهده اطلاعات ماژول
modinfo kernel_driver.ko
```

## بهینه‌سازی عملکرد

### 1. تنظیمات حافظه
- بافر اشتراکی: 16KB (قابل تغییر)
- استفاده از mmap برای داده‌های حجیم
- کش کردن اطلاعات در userland

### 2. کاهش overhead
- استفاده از IOCTL برای عملیات سریع
- netlink برای ارتباط آسنکرون
- Batch processing برای چندین درخواست

### 3. مدیریت منابع
- آزادسازی خودکار منابع
- error handling کامل
- memory leak prevention

## امنیت

### محدودیت‌های امنیتی
- بررسی دسترسی‌های کاربر
- محدودیت در اطلاعات قابل دسترس
- لاگ‌گذاری تمام عملیات

### توصیه‌های امنیتی
- اجرا با کمترین دسترسی لازم
- مراقبت از shared memory
- نظارت بر لاگ‌های سیستم

## حذف درایور

```bash
# حذف درایور از حافظه
sudo rmmod kernel_driver

# یا:
sudo make -f Makefile.kernel uninstall

# پاک‌سازی فایل‌ها
make -f Makefile.kernel clean
```

## نکات مهم نسخه 2.0

1. **سازگاری کرنل**: این نسخه مخصوص کرنل‌های 6.x طراحی شده
2. **بهبود عملکرد**: بافر اشتراکی بزرگ‌تر و الگوریتم‌های بهینه
3. **API های جدید**: 8 IOCTL جدید با قابلیت‌های پیشرفته  
4. **لاگ‌گذاری**: سیستم لاگ‌گذاری کامل برای عیب‌یابی
5. **مدیریت خطا**: error handling پیشرفته در تمام لایه‌ها

این درایور یک پلتفرم کامل و حرفه‌ای برای توسعه ابزارهای سیستمی پیشرفته ارائه می‌دهد که امکان دسترسی عمیق و کنترل کامل بر قابلیت‌های کرنل لینوکس را از طریق Python فراهم می‌کند.

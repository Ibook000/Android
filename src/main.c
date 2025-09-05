#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/sched.h>

#include "kpm_api.h"

#define MODULE_NAME "AntiWipe"
#define MODULE_VERSION "1.0.0"
#define MODULE_AUTHOR "KernelSU Community"

// 危险分区列表
static const char *dangerous_partitions[] = {
    "persist", "vm-persist", "modem_a", "modem_b", 
    "modemst1", "modemst2", "fsg", "fsc",
    "abl_a", "abl_b", "featenabler_a", "featenabler_b",
    "xbl_a", "xbl_b", "xbl_config_a", "xbl_config_b",
    "xbl_ramdump_a", "xbl_ramdump_b", "xbl_sc_logs",
    "xbl_sc_test_mode", "vendor_boot_a", "vendor_boot_b", "ocdt",
    NULL
};

// 危险命令列表
static const char *dangerous_commands[] = {
    "dd", "mkfs", "format", "wipe", NULL
};

static struct kprobe kp_sys_open;
static struct kprobe kp_sys_openat;
static struct kprobe kp_sys_unlink;
static struct kprobe kp_sys_unlinkat;
static struct kprobe kp_sys_execve;

static bool waiting_for_input = false;
static bool user_confirmed = false;
static DEFINE_MUTEX(confirm_mutex);

// 检查是否为危险分区
static bool is_dangerous_partition(const char *path) {
    int i;
    if (!path) return false;
    
    for (i = 0; dangerous_partitions[i]; i++) {
        if (strstr(path, dangerous_partitions[i])) {
            return true;
        }
    }
    return false;
}

// 检查是否为危险命令
static bool is_dangerous_command(const char *cmd) {
    int i;
    if (!cmd) return false;
    
    for (i = 0; dangerous_commands[i]; i++) {
        if (strstr(cmd, dangerous_commands[i])) {
            return true;
        }
    }
    return false;
}

// 等待用户确认
static bool wait_for_user_confirmation(const char *operation) {
    int timeout = 50; // 5秒超时 (50 * 100ms)
    
    mutex_lock(&confirm_mutex);
    waiting_for_input = true;
    user_confirmed = false;
    
    pr_warn("[%s] Dangerous operation detected: %s\n", MODULE_NAME, operation);
    pr_warn("[%s] Press Volume+ to confirm, Volume- to deny (5s timeout)\n", MODULE_NAME);
    
    while (timeout-- > 0 && waiting_for_input) {
        msleep(100);
    }
    
    waiting_for_input = false;
    bool result = user_confirmed;
    mutex_unlock(&confirm_mutex);
    
    return result;
}

// Hook sys_open
static int hook_sys_open(struct kprobe *p, struct pt_regs *regs) {
    const char __user *filename = (const char __user *)regs->regs[0];
    int flags = (int)regs->regs[1];
    char *kname;
    int ret = 0;
    
    kname = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kname) return 0;
    
    if (strncpy_from_user(kname, filename, PATH_MAX) > 0) {
        // 检查是否尝试打开危险分区进行写操作
        if ((flags & O_WRONLY) || (flags & O_RDWR)) {
            if (is_dangerous_partition(kname)) {
                pr_err("[%s] Blocked write access to dangerous partition: %s\n", 
                       MODULE_NAME, kname);
                ret = -EACCES;
            }
        }
    }
    
    kfree(kname);
    return ret;
}

// Hook sys_execve
static int hook_sys_execve(struct kprobe *p, struct pt_regs *regs) {
    const char __user *filename = (const char __user *)regs->regs[0];
    char *kname;
    int ret = 0;
    
    kname = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kname) return 0;
    
    if (strncpy_from_user(kname, filename, PATH_MAX) > 0) {
        if (is_dangerous_command(kname)) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Execute dangerous command: %s", kname);
            
            if (!wait_for_user_confirmation(msg)) {
                pr_err("[%s] User denied execution of: %s\n", MODULE_NAME, kname);
                ret = -EACCES;
            }
        }
    }
    
    kfree(kname);
    return ret;
}

// Hook sys_unlink/unlinkat
static int hook_sys_unlink(struct kprobe *p, struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->regs[0];
    char *kname;
    int ret = 0;
    
    kname = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kname) return 0;
    
    if (strncpy_from_user(kname, pathname, PATH_MAX) > 0) {
        // 阻止删除 /dev/input/* 文件
        if (strstr(kname, "/dev/input/")) {
            pr_err("[%s] Blocked deletion of input device: %s\n", MODULE_NAME, kname);
            ret = -EACCES;
        }
    }
    
    kfree(kname);
    return ret;
}

// 音量键监听器
static int volume_key_notifier(struct notifier_block *nb, 
                              unsigned long code, void *data) {
    struct input_event *event = data;
    
    if (!waiting_for_input) return NOTIFY_OK;
    
    if (event->type == EV_KEY) {
        if (event->code == KEY_VOLUMEUP && event->value == 1) {
            user_confirmed = true;
            waiting_for_input = false;
            pr_info("[%s] User confirmed operation\n", MODULE_NAME);
        } else if (event->code == KEY_VOLUMEDOWN && event->value == 1) {
            user_confirmed = false;
            waiting_for_input = false;
            pr_info("[%s] User denied operation\n", MODULE_NAME);
        }
    }
    
    return NOTIFY_OK;
}

static struct notifier_block volume_key_nb = {
    .notifier_call = volume_key_notifier,
};

// KPM 初始化
int kpm_init(void) {
    int ret;
    
    pr_info("[%s] Initializing module v%s\n", MODULE_NAME, MODULE_VERSION);
    
    // 注册 kprobes
    kp_sys_open.symbol_name = "sys_open";
    kp_sys_open.pre_handler = hook_sys_open;
    ret = register_kprobe(&kp_sys_open);
    if (ret < 0) {
        pr_err("[%s] Failed to register kprobe for sys_open\n", MODULE_NAME);
    }
    
    kp_sys_openat.symbol_name = "sys_openat";
    kp_sys_openat.pre_handler = hook_sys_open;
    register_kprobe(&kp_sys_openat);
    
    kp_sys_execve.symbol_name = "sys_execve";
    kp_sys_execve.pre_handler = hook_sys_execve;
    register_kprobe(&kp_sys_execve);
    
    kp_sys_unlink.symbol_name = "sys_unlink";
    kp_sys_unlink.pre_handler = hook_sys_unlink;
    register_kprobe(&kp_sys_unlink);
    
    kp_sys_unlinkat.symbol_name = "sys_unlinkat";
    kp_sys_unlinkat.pre_handler = hook_sys_unlink;
    register_kprobe(&kp_sys_unlinkat);
    
    pr_info("[%s] Module loaded successfully\n", MODULE_NAME);
    return 0;
}

// KPM 退出
void kpm_exit(void) {
    unregister_kprobe(&kp_sys_open);
    unregister_kprobe(&kp_sys_openat);
    unregister_kprobe(&kp_sys_execve);
    unregister_kprobe(&kp_sys_unlink);
    unregister_kprobe(&kp_sys_unlinkat);
    
    pr_info("[%s] Module unloaded\n", MODULE_NAME);
}

KPM_MODULE_LICENSE("GPL");
KPM_MODULE_AUTHOR(MODULE_AUTHOR);
KPM_MODULE_DESCRIPTION("Anti-wipe protection module for KernelSU");
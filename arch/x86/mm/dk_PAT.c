#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>

#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/pat.h>
#include <asm/page_types.h>
#include <asm/set_memory.h>
#include <asm-generic/set_memory.h>

SYSCALL_DEFINE2(set_memory_uc_dk_wrapper, unsigned long, addr, int, numpages){
    //printk(KERN_INFO "set_memory_uc systemcall begin\n");
    return set_memory_uc_PAT_user(addr, numpages);
}
SYSCALL_DEFINE2(set_memory_wc_dk_wrapper, unsigned long, addr, int, numpages){
    //printk(KERN_INFO "set_memory_wc systemcall begin\n");
    return set_memory_wc_PAT_user(addr, numpages);
}
SYSCALL_DEFINE2(set_memory_wt_dk_wrapper, unsigned long, addr, int, numpages){
    //printk(KERN_INFO "set_memory_wt systemcall begin\n");
    return set_memory_wt_PAT_user(addr, numpages);
}
SYSCALL_DEFINE2(set_memory_wb_dk_wrapper, unsigned long, addr, int, numpages){
    //printk(KERN_INFO "set_memory_wb systemcall begin\n");
    return set_memory_wb_PAT_user(addr, numpages);
}
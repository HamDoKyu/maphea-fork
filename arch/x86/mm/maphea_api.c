#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>

#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/pat.h>
#include <asm/page_types.h>
#include <asm-generic/set_memory.h>

SYSCALL_DEFINE2(set_pages_uc, unsigned long, addr, int, numpages)
{
  int ret;

  ret = reserve_memtype_maphea(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
                               _PAGE_CACHE_MODE_UC_MINUS, NULL);

  // printk("[MaPHeA Message] reserve_memtype %lx, %lx, %d, ret: %d\n", addr, __pa(addr), numpages, ret);

  if (ret) 
    goto out_err;

  // printk("[MaPHeA Message] set_memory_uc %lx, %d\n", addr, numpages);
  ret = change_page_attr_set_clr_maphea(&addr, numpages, 
                                        cachemode2pgprot(_PAGE_CACHE_MODE_UC_MINUS), 
                                        __pgprot(0),
                                        NULL);

  // printk("[MaPHeA Message] change_page_attr_set_clr_maphea %d\n", ret);
  if (ret)
    goto out_free;

  return 0;

out_free:
  free_memtype_maphea(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);

out_err:
  return ret;
}

SYSCALL_DEFINE2(set_pages_wc, unsigned long, addr, int, numpages)
{
  int ret;

  ret = reserve_memtype_maphea(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
                               _PAGE_CACHE_MODE_WC, NULL);
  if (ret) 
    return ret;

  // printk("[MaPHeA Message] set_memory_wc %lx, %d\n", addr, numpages);
  ret = change_page_attr_set_clr_maphea(&addr, numpages, 
                                        cachemode2pgprot(_PAGE_CACHE_MODE_UC_MINUS), 
                                        __pgprot(0),
                                        NULL);

  if (!ret) {
    ret = change_page_attr_set_clr_maphea(&addr, numpages,
                                          cachemode2pgprot(_PAGE_CACHE_MODE_WC),
                                          __pgprot(_PAGE_CACHE_MASK),
                                          NULL);
  }

  if (ret)
    free_memtype_maphea(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);

  return ret;
}

SYSCALL_DEFINE2(set_pages_wt, unsigned long, addr, int, numpages)
{
  int ret;

  ret = reserve_memtype_maphea(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
                               _PAGE_CACHE_MODE_WT, NULL);
  if (ret) 
    return ret;

  // printk("[MaPHeA Message] set_memory_wt %lx, %d\n", addr, numpages);
  ret = change_page_attr_set_clr_maphea(&addr, numpages, 
                                        cachemode2pgprot(_PAGE_CACHE_MODE_WT), 
                                        __pgprot(0),
                                        NULL);

  if (ret)
    free_memtype_maphea(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);

  return ret;
}

SYSCALL_DEFINE2(free_pages_memtype, unsigned long, addr, int, numpages)
{
  // printk("[MaPHeA Message] free_pages_memtype %lx, %d\n", addr, numpages);
  free_memtype_maphea(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);

  return 0;
}

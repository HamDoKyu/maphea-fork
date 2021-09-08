/*
 * Copyright 2002 Andi Kleen, SuSE Labs.
 * Thanks to Ben LaHaise for precious feedback.
 */
#include <linux/highmem.h>
#include <linux/memblock.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/pfn.h>
#include <linux/percpu.h>
#include <linux/gfp.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>

#include <asm/e820/api.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <linux/uaccess.h>
#include <asm/pgalloc.h>
#include <asm/proto.h>
#include <asm/pat.h>
#include <asm/set_memory.h>
#include <asm/uaccess.h>
/*
 * The current flushing context - we pass it instead of 5 arguments:
 */
struct cpa_data {
	unsigned long	*vaddr;
	pgd_t		*pgd;
	pgprot_t	mask_set;
	pgprot_t	mask_clr;
	unsigned long	numpages;
	int		flags;
	unsigned long	pfn;
	unsigned	force_split		: 1,
			force_static_prot	: 1;
	int		curpage;
	struct page	**pages;
};

enum cpa_warn {
	CPA_CONFLICT,
	CPA_PROTECT,
	CPA_DETECT,
};

static const int cpa_warn_level = CPA_PROTECT;

/*
 * Serialize cpa() (for !DEBUG_PAGEALLOC which uses large identity mappings)
 * using cpa_lock. So that we don't allow any other cpu, with stale large tlb
 * entries change the page attribute in parallel to some other cpu
 * splitting a large page entry along with changing the attribute.
 */
static DEFINE_SPINLOCK(cpa_lock);

#define CPA_FLUSHTLB 1
#define CPA_ARRAY 2
#define CPA_PAGES_ARRAY 4
#define CPA_NO_CHECK_ALIAS 8 /* Do not search for aliases */

#ifdef CONFIG_PROC_FS
static unsigned long direct_pages_count[PG_LEVEL_NUM];



static void split_page_count(int level)
{
	if (direct_pages_count[level] == 0)
		return;

	direct_pages_count[level]--;
	direct_pages_count[level - 1] += PTRS_PER_PTE;
}


#else
static inline void split_page_count(int level) { }
#endif

#ifdef CONFIG_X86_CPA_STATISTICS

static unsigned long cpa_1g_checked;
static unsigned long cpa_1g_sameprot;
static unsigned long cpa_1g_preserved;
static unsigned long cpa_2m_checked;
static unsigned long cpa_2m_sameprot;
static unsigned long cpa_2m_preserved;
static unsigned long cpa_4k_install;

static inline void cpa_inc_1g_checked(void)
{
	cpa_1g_checked++;
}

static inline void cpa_inc_2m_checked(void)
{
	cpa_2m_checked++;
}

static inline void cpa_inc_4k_install(void)
{
	cpa_4k_install++;
}

static inline void cpa_inc_lp_sameprot(int level)
{
	if (level == PG_LEVEL_1G)
		cpa_1g_sameprot++;
	else
		cpa_2m_sameprot++;
}

static inline void cpa_inc_lp_preserved(int level)
{
	if (level == PG_LEVEL_1G)
		cpa_1g_preserved++;
	else
		cpa_2m_preserved++;
}

static int cpastats_show(struct seq_file *m, void *p)
{
	seq_printf(m, "1G pages checked:     %16lu\n", cpa_1g_checked);
	seq_printf(m, "1G pages sameprot:    %16lu\n", cpa_1g_sameprot);
	seq_printf(m, "1G pages preserved:   %16lu\n", cpa_1g_preserved);
	seq_printf(m, "2M pages checked:     %16lu\n", cpa_2m_checked);
	seq_printf(m, "2M pages sameprot:    %16lu\n", cpa_2m_sameprot);
	seq_printf(m, "2M pages preserved:   %16lu\n", cpa_2m_preserved);
	seq_printf(m, "4K pages set-checked: %16lu\n", cpa_4k_install);
	return 0;
}

static int cpastats_open(struct inode *inode, struct file *file)
{
	return single_open(file, cpastats_show, NULL);
}

static const struct file_operations cpastats_fops = {
	.open		= cpastats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init cpa_stats_init(void)
{
	debugfs_create_file("cpa_stats_PAT_version", S_IRUSR, arch_debugfs_dir, NULL,
			    &cpastats_fops);
	return 0;
}
late_initcall(cpa_stats_init);
#else
static inline void cpa_inc_1g_checked(void) { }
static inline void cpa_inc_2m_checked(void) { }
static inline void cpa_inc_4k_install(void) { }
static inline void cpa_inc_lp_sameprot(int level) { }
static inline void cpa_inc_lp_preserved(int level) { }
#endif


static inline int
within(unsigned long addr, unsigned long start, unsigned long end)
{
	return addr >= start && addr < end;
}

static inline int
within_inclusive(unsigned long addr, unsigned long start, unsigned long end)
{
	return addr >= start && addr <= end;
}

#ifdef CONFIG_X86_64

static inline unsigned long highmap_start_pfn(void)
{
	return __pa_symbol(_text) >> PAGE_SHIFT;
}

static inline unsigned long highmap_end_pfn(void)
{
	/* Do not reference physical address outside the kernel. */
	return __pa_symbol(roundup(_brk_end, PMD_SIZE) - 1) >> PAGE_SHIFT;
}

static bool __cpa_pfn_in_highmap(unsigned long pfn)
{
	/*
	 * Kernel text has an alias mapping at a high address, known
	 * here as "highmap".
	 */
	return within_inclusive(pfn, highmap_start_pfn(), highmap_end_pfn());
}

#else

static bool __cpa_pfn_in_highmap(unsigned long pfn)
{
	/* There is no highmap on 32-bit */
	return false;
}

#endif

/*
 * Flushing functions
 */

/**
 * clflush_cache_range - flush a cache range with clflush
 * @vaddr:	virtual start address
 * @size:	number of bytes to flush
 *
 * clflushopt is an unordered instruction which needs fencing with mfence or
 * sfence to avoid ordering issues.
 */



static void __cpa_flush_all(void *arg)
{
	unsigned long cache = (unsigned long)arg;

	/*
	 * Flush all to work around Errata in early athlons regarding
	 * large page flushing.
	 */
	__flush_tlb_all();

	if (cache && boot_cpu_data.x86 >= 4)
		wbinvd();
}

static void cpa_flush_all(unsigned long cache)
{
	BUG_ON(irqs_disabled() && !early_boot_irqs_disabled);

	on_each_cpu(__cpa_flush_all, (void *) cache, 1);
}

static bool __inv_flush_all(int cache)
{
	BUG_ON(irqs_disabled() && !early_boot_irqs_disabled);

	if (cache && !static_cpu_has(X86_FEATURE_CLFLUSH)) {
		cpa_flush_all(cache);
		return true;
	}

	return false;
}

static void cpa_flush_range(unsigned long start, int numpages, int cache)
{
	unsigned int i, level;
	unsigned long addr;

	WARN_ON(PAGE_ALIGN(start) != start);

	if (__inv_flush_all(cache))
		return;

	flush_tlb_kernel_range(start, start + PAGE_SIZE * numpages);

	if (!cache)
		return;

	/*
	 * We only need to flush on one CPU,
	 * clflush is a MESI-coherent instruction that
	 * will cause all other CPUs to flush the same
	 * cachelines:
	 */
	for (i = 0, addr = start; i < numpages; i++, addr += PAGE_SIZE) {
		pte_t *pte = lookup_address(addr, &level);

		/*
		 * Only flush present addresses:
		 */
		if (pte && (pte_val(*pte) & _PAGE_PRESENT))
			clflush_cache_range((void *) addr, PAGE_SIZE);
	}
}

static void cpa_flush_array(unsigned long baddr, unsigned long *start,
			    int numpages, int cache,
			    int in_flags, struct page **pages)
{
	unsigned int i, level;

	if (__inv_flush_all(cache))
		return;

	flush_tlb_all();

	if (!cache)
		return;

	/*
	 * We only need to flush on one CPU,
	 * clflush is a MESI-coherent instruction that
	 * will cause all other CPUs to flush the same
	 * cachelines:
	 */
	for (i = 0; i < numpages; i++) {
		unsigned long addr;
		pte_t *pte;

		if (in_flags & CPA_PAGES_ARRAY)
			addr = (unsigned long)page_address(pages[i]);
		else
			addr = start[i];

		pte = lookup_address(addr, &level);

		/*
		 * Only flush present addresses:
		 */
		if (pte && (pte_val(*pte) & _PAGE_PRESENT))
			clflush_cache_range((void *)addr, PAGE_SIZE);
	}
}

static bool overlaps(unsigned long r1_start, unsigned long r1_end,
		     unsigned long r2_start, unsigned long r2_end)
{
	return (r1_start <= r2_end && r1_end >= r2_start) ||
		(r2_start <= r1_end && r2_end >= r1_start);
}

#ifdef CONFIG_PCI_BIOS
/*
 * The BIOS area between 640k and 1Mb needs to be executable for PCI BIOS
 * based config access (CONFIG_PCI_GOBIOS) support.
 */
#define BIOS_PFN	PFN_DOWN(BIOS_BEGIN)
#define BIOS_PFN_END	PFN_DOWN(BIOS_END - 1)

static pgprotval_t protect_pci_bios(unsigned long spfn, unsigned long epfn)
{
	if (pcibios_enabled && overlaps(spfn, epfn, BIOS_PFN, BIOS_PFN_END))
		return _PAGE_NX;
	return 0;
}
#else
static pgprotval_t protect_pci_bios(unsigned long spfn, unsigned long epfn)
{
	return 0;
}
#endif

/*
 * The .rodata section needs to be read-only. Using the pfn catches all
 * aliases.  This also includes __ro_after_init, so do not enforce until
 * kernel_set_to_readonly is true.
 */
static pgprotval_t protect_rodata(unsigned long spfn, unsigned long epfn)
{
	unsigned long epfn_ro, spfn_ro = PFN_DOWN(__pa_symbol(__start_rodata));

	/*
	 * Note: __end_rodata is at page aligned and not inclusive, so
	 * subtract 1 to get the last enforced PFN in the rodata area.
	 */
	epfn_ro = PFN_DOWN(__pa_symbol(__end_rodata)) - 1;

	if (kernel_set_to_readonly && overlaps(spfn, epfn, spfn_ro, epfn_ro))
		return _PAGE_RW;
	return 0;
}

/*
 * Protect kernel text against becoming non executable by forbidding
 * _PAGE_NX.  This protects only the high kernel mapping (_text -> _etext)
 * out of which the kernel actually executes.  Do not protect the low
 * mapping.
 *
 * This does not cover __inittext since that is gone after boot.
 */
static pgprotval_t protect_kernel_text(unsigned long start, unsigned long end)
{
	unsigned long t_end = (unsigned long)_etext - 1;
	unsigned long t_start = (unsigned long)_text;

	if (overlaps(start, end, t_start, t_end))
		return _PAGE_NX;
	return 0;
}

#if defined(CONFIG_X86_64)
/*
 * Once the kernel maps the text as RO (kernel_set_to_readonly is set),
 * kernel text mappings for the large page aligned text, rodata sections
 * will be always read-only. For the kernel identity mappings covering the
 * holes caused by this alignment can be anything that user asks.
 *
 * This will preserve the large page mappings for kernel text/data at no
 * extra cost.
 */
static pgprotval_t protect_kernel_text_ro(unsigned long start,
					  unsigned long end)
{
	unsigned long t_end = (unsigned long)__end_rodata_hpage_align - 1;
	unsigned long t_start = (unsigned long)_text;
	unsigned int level;

	if (!kernel_set_to_readonly || !overlaps(start, end, t_start, t_end))
		return 0;
	/*
	 * Don't enforce the !RW mapping for the kernel text mapping, if
	 * the current mapping is already using small page mapping.  No
	 * need to work hard to preserve large page mappings in this case.
	 *
	 * This also fixes the Linux Xen paravirt guest boot failure caused
	 * by unexpected read-only mappings for kernel identity
	 * mappings. In this paravirt guest case, the kernel text mapping
	 * and the kernel identity mapping share the same page-table pages,
	 * so the protections for kernel text and identity mappings have to
	 * be the same.
	 */
	if (lookup_address(start, &level) && (level != PG_LEVEL_4K))
		return _PAGE_RW;
	return 0;
}
#else
static pgprotval_t protect_kernel_text_ro(unsigned long start,
					  unsigned long end)
{
	return 0;
}
#endif

static inline bool conflicts(pgprot_t prot, pgprotval_t val)
{
	return (pgprot_val(prot) & ~val) != pgprot_val(prot);
}

static inline void check_conflict(int warnlvl, pgprot_t prot, pgprotval_t val,
				  unsigned long start, unsigned long end,
				  unsigned long pfn, const char *txt)
{
	static const char *lvltxt[] = {
		[CPA_CONFLICT]	= "conflict",
		[CPA_PROTECT]	= "protect",
		[CPA_DETECT]	= "detect",
	};

	if (warnlvl > cpa_warn_level || !conflicts(prot, val))
		return;

	pr_warn("CPA %8s %10s: 0x%016lx - 0x%016lx PFN %lx req %016llx prevent %016llx\n",
		lvltxt[warnlvl], txt, start, end, pfn, (unsigned long long)pgprot_val(prot),
		(unsigned long long)val);
}

/*
 * Certain areas of memory on x86 require very specific protection flags,
 * for example the BIOS area or kernel text. Callers don't always get this
 * right (again, ioremap() on BIOS memory is not uncommon) so this function
 * checks and fixes these known static required protection bits.
 */
static inline pgprot_t static_protections(pgprot_t prot, unsigned long start,
					  unsigned long pfn, unsigned long npg,
					  int warnlvl)
{
	pgprotval_t forbidden, res;
	unsigned long end;

	/*
	 * There is no point in checking RW/NX conflicts when the requested
	 * mapping is setting the page !PRESENT.
	 */
	if (!(pgprot_val(prot) & _PAGE_PRESENT))
		return prot;

	/* Operate on the virtual address */
	end = start + npg * PAGE_SIZE - 1;

	res = protect_kernel_text(start, end);
	check_conflict(warnlvl, prot, res, start, end, pfn, "Text NX");
	forbidden = res;

	res = protect_kernel_text_ro(start, end);
	check_conflict(warnlvl, prot, res, start, end, pfn, "Text RO");
	forbidden |= res;

	/* Check the PFN directly */
	res = protect_pci_bios(pfn, pfn + npg - 1);
	check_conflict(warnlvl, prot, res, start, end, pfn, "PCIBIOS NX");
	forbidden |= res;

	res = protect_rodata(pfn, pfn + npg - 1);
	check_conflict(warnlvl, prot, res, start, end, pfn, "Rodata RO");
	forbidden |= res;

	return __pgprot(pgprot_val(prot) & ~forbidden);
}

/*
 * 
lookup_address_in_pgd
lookup_address
lookup_pmd_address
slow_virt_to_phys

 are pre-implemented in pageattr.c
 */


/*
 * Lookup for change page attribute
 */


static pte_t *_lookup_address_cpa(struct cpa_data *cpa, unsigned long address,
				  unsigned int *level)
{
	if (cpa->pgd){
		return lookup_address_in_pgd(cpa->pgd + pgd_index(address),
					       address, level);
	}
	//To validate for the system call s.t. current returns the caller's mm.
	return lookup_address_in_pgd(pgd_offset(current->mm, address), address, level);
}

/*
 * Set the new pmd in all the pgds we know about:
 */
static void __set_pmd_pte(pte_t *kpte, unsigned long address, pte_t pte)
{
	/* change init_mm */
	set_pte_atomic(kpte, pte);
#ifdef CONFIG_X86_32
	if (!SHARED_KERNEL_PMD) {
		struct page *page;

		list_for_each_entry(page, &pgd_list, lru) {
			pgd_t *pgd;
			p4d_t *p4d;
			pud_t *pud;
			pmd_t *pmd;

			pgd = (pgd_t *)page_address(page) + pgd_index(address);
			p4d = p4d_offset(pgd, address);
			pud = pud_offset(p4d, address);
			pmd = pmd_offset(pud, address);
			set_pte_atomic((pte_t *)pmd, pte);
		}
	}
#endif
}

static pgprot_t pgprot_clear_protnone_bits(pgprot_t prot)
{
	/*
	 * _PAGE_GLOBAL means "global page" for present PTEs.
	 * But, it is also used to indicate _PAGE_PROTNONE
	 * for non-present PTEs.
	 *
	 * This ensures that a _PAGE_GLOBAL PTE going from
	 * present to non-present is not confused as
	 * _PAGE_PROTNONE.
	 */
	if (!(pgprot_val(prot) & _PAGE_PRESENT))
		pgprot_val(prot) &= ~_PAGE_GLOBAL;

	return prot;
}

static int __should_split_large_page(pte_t *kpte, unsigned long address,
				     struct cpa_data *cpa)
{
	unsigned long numpages, pmask, psize, lpaddr, pfn, old_pfn;
	pgprot_t old_prot, new_prot, req_prot, chk_prot;
	pte_t new_pte, old_pte, *tmp;
	enum pg_level level;

	/*
	 * Check for races, another CPU might have split this page
	 * up already:
	 */
	tmp = _lookup_address_cpa(cpa, address, &level);
	if (tmp != kpte)
		return 1;

	switch (level) {
	case PG_LEVEL_2M:
		old_prot = pmd_pgprot(*(pmd_t *)kpte);
		old_pfn = pmd_pfn(*(pmd_t *)kpte);
		cpa_inc_2m_checked();
		break;
	case PG_LEVEL_1G:
		old_prot = pud_pgprot(*(pud_t *)kpte);
		old_pfn = pud_pfn(*(pud_t *)kpte);
		cpa_inc_1g_checked();
		break;
	default:
		return -EINVAL;
	}

	psize = page_level_size(level);
	pmask = page_level_mask(level);

	/*
	 * Calculate the number of pages, which fit into this large
	 * page starting at address:
	 */
	lpaddr = (address + psize) & pmask;
	numpages = (lpaddr - address) >> PAGE_SHIFT;
	if (numpages < cpa->numpages)
		cpa->numpages = numpages;

	/*
	 * We are safe now. Check whether the new pgprot is the same:
	 * Convert protection attributes to 4k-format, as cpa->mask* are set
	 * up accordingly.
	 */
	old_pte = *kpte;
	/* Clear PSE (aka _PAGE_PAT) and move PAT bit to correct position */
	req_prot = pgprot_large_2_4k(old_prot);

	pgprot_val(req_prot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(req_prot) |= pgprot_val(cpa->mask_set);

	/*
	 * req_prot is in format of 4k pages. It must be converted to large
	 * page format: the caching mode includes the PAT bit located at
	 * different bit positions in the two formats.
	 */
	req_prot = pgprot_4k_2_large(req_prot);
	req_prot = pgprot_clear_protnone_bits(req_prot);
	if (pgprot_val(req_prot) & _PAGE_PRESENT)
		pgprot_val(req_prot) |= _PAGE_PSE;

	/*
	 * old_pfn points to the large page base pfn. So we need to add the
	 * offset of the virtual address:
	 */
	pfn = old_pfn + ((address & (psize - 1)) >> PAGE_SHIFT);
	cpa->pfn = pfn;

	/*
	 * Calculate the large page base address and the number of 4K pages
	 * in the large page
	 */
	lpaddr = address & pmask;
	numpages = psize >> PAGE_SHIFT;

	/*
	 * Sanity check that the existing mapping is correct versus the static
	 * protections. static_protections() guards against !PRESENT, so no
	 * extra conditional required here.
	 */
	chk_prot = static_protections(old_prot, lpaddr, old_pfn, numpages,
				      CPA_CONFLICT);

	if (WARN_ON_ONCE(pgprot_val(chk_prot) != pgprot_val(old_prot))) {
		/*
		 * Split the large page and tell the split code to
		 * enforce static protections.
		 */
		cpa->force_static_prot = 1;
		return 1;
	}

	/*
	 * Optimization: If the requested pgprot is the same as the current
	 * pgprot, then the large page can be preserved and no updates are
	 * required independent of alignment and length of the requested
	 * range. The above already established that the current pgprot is
	 * correct, which in consequence makes the requested pgprot correct
	 * as well if it is the same. The static protection scan below will
	 * not come to a different conclusion.
	 */
	if (pgprot_val(req_prot) == pgprot_val(old_prot)) {
		cpa_inc_lp_sameprot(level);
		return 0;
	}

	/*
	 * If the requested range does not cover the full page, split it up
	 */
	if (address != lpaddr || cpa->numpages != numpages)
		return 1;

	/*
	 * Check whether the requested pgprot is conflicting with a static
	 * protection requirement in the large page.
	 */
	new_prot = static_protections(req_prot, lpaddr, old_pfn, numpages,
				      CPA_DETECT);

	/*
	 * If there is a conflict, split the large page.
	 *
	 * There used to be a 4k wise evaluation trying really hard to
	 * preserve the large pages, but experimentation has shown, that this
	 * does not help at all. There might be corner cases which would
	 * preserve one large page occasionally, but it's really not worth the
	 * extra code and cycles for the common case.
	 */
	if (pgprot_val(req_prot) != pgprot_val(new_prot))
		return 1;

	/* All checks passed. Update the large page mapping. */
	new_pte = pfn_pte(old_pfn, new_prot);
	__set_pmd_pte(kpte, address, new_pte);
	cpa->flags |= CPA_FLUSHTLB;
	cpa_inc_lp_preserved(level);
	return 0;
}

static int should_split_large_page(pte_t *kpte, unsigned long address,
				   struct cpa_data *cpa)
{
	int do_split;

	if (cpa->force_split)
		return 1;

	spin_lock(&pgd_lock);
	do_split = __should_split_large_page(kpte, address, cpa);
	spin_unlock(&pgd_lock);

	return do_split;
}

static void split_set_pte(struct cpa_data *cpa, pte_t *pte, unsigned long pfn,
			  pgprot_t ref_prot, unsigned long address,
			  unsigned long size)
{
	unsigned int npg = PFN_DOWN(size);
	pgprot_t prot;

	/*
	 * If should_split_large_page() discovered an inconsistent mapping,
	 * remove the invalid protection in the split mapping.
	 */
	if (!cpa->force_static_prot)
		goto set;

	prot = static_protections(ref_prot, address, pfn, npg, CPA_PROTECT);

	if (pgprot_val(prot) == pgprot_val(ref_prot))
		goto set;

	/*
	 * If this is splitting a PMD, fix it up. PUD splits cannot be
	 * fixed trivially as that would require to rescan the newly
	 * installed PMD mappings after returning from split_large_page()
	 * so an eventual further split can allocate the necessary PTE
	 * pages. Warn for now and revisit it in case this actually
	 * happens.
	 */
	if (size == PAGE_SIZE)
		ref_prot = prot;
	else
		pr_warn_once("CPA: Cannot fixup static protections for PUD split\n");
set:
	set_pte(pte, pfn_pte(pfn, ref_prot));
}

static int
__split_large_page(struct cpa_data *cpa, pte_t *kpte, unsigned long address,
		   struct page *base)
{
	unsigned long lpaddr, lpinc, ref_pfn, pfn, pfninc = 1;
	pte_t *pbase = (pte_t *)page_address(base);
	unsigned int i, level;
	pgprot_t ref_prot;
	pte_t *tmp;

	spin_lock(&pgd_lock);
	/*
	 * Check for races, another CPU might have split this page
	 * up for us already:
	 */
	tmp = _lookup_address_cpa(cpa, address, &level);
	if (tmp != kpte) {
		spin_unlock(&pgd_lock);
		return 1;
	}

	paravirt_alloc_pte(&init_mm, page_to_pfn(base));

	switch (level) {
	case PG_LEVEL_2M:
		ref_prot = pmd_pgprot(*(pmd_t *)kpte);
		/*
		 * Clear PSE (aka _PAGE_PAT) and move
		 * PAT bit to correct position.
		 */
		ref_prot = pgprot_large_2_4k(ref_prot);
		ref_pfn = pmd_pfn(*(pmd_t *)kpte);
		lpaddr = address & PMD_MASK;
		lpinc = PAGE_SIZE;
		break;

	case PG_LEVEL_1G:
		ref_prot = pud_pgprot(*(pud_t *)kpte);
		ref_pfn = pud_pfn(*(pud_t *)kpte);
		pfninc = PMD_PAGE_SIZE >> PAGE_SHIFT;
		lpaddr = address & PUD_MASK;
		lpinc = PMD_SIZE;
		/*
		 * Clear the PSE flags if the PRESENT flag is not set
		 * otherwise pmd_present/pmd_huge will return true
		 * even on a non present pmd.
		 */
		if (!(pgprot_val(ref_prot) & _PAGE_PRESENT))
			pgprot_val(ref_prot) &= ~_PAGE_PSE;
		break;

	default:
		spin_unlock(&pgd_lock);
		return 1;
	}

	ref_prot = pgprot_clear_protnone_bits(ref_prot);

	/*
	 * Get the target pfn from the original entry:
	 */
	pfn = ref_pfn;
	for (i = 0; i < PTRS_PER_PTE; i++, pfn += pfninc, lpaddr += lpinc)
		split_set_pte(cpa, pbase + i, pfn, ref_prot, lpaddr, lpinc);

	if (virt_addr_valid(address)) {
		unsigned long pfn = PFN_DOWN(__pa(address));

		if (pfn_range_is_mapped(pfn, pfn + 1))
			split_page_count(level);
	}

	/*
	 * Install the new, split up pagetable.
	 *
	 * We use the standard kernel pagetable protections for the new
	 * pagetable protections, the actual ptes set above control the
	 * primary protection behavior:
	 */
	__set_pmd_pte(kpte, address, mk_pte(base, __pgprot(_KERNPG_TABLE)));

	/*
	 * Do a global flush tlb after splitting the large page
	 * and before we do the actual change page attribute in the PTE.
	 *
	 * Without this, we violate the TLB application note, that says:
	 * "The TLBs may contain both ordinary and large-page
	 *  translations for a 4-KByte range of linear addresses. This
	 *  may occur if software modifies the paging structures so that
	 *  the page size used for the address range changes. If the two
	 *  translations differ with respect to page frame or attributes
	 *  (e.g., permissions), processor behavior is undefined and may
	 *  be implementation-specific."
	 *
	 * We do this global tlb flush inside the cpa_lock, so that we
	 * don't allow any other cpu, with stale tlb entries change the
	 * page attribute in parallel, that also falls into the
	 * just split large page entry.
	 */
	flush_tlb_all();
	spin_unlock(&pgd_lock);

	return 0;
}

static int split_large_page(struct cpa_data *cpa, pte_t *kpte,
			    unsigned long address)
{
	struct page *base;

	if (!debug_pagealloc_enabled())
		spin_unlock(&cpa_lock);
	base = alloc_pages(GFP_KERNEL, 0);
	if (!debug_pagealloc_enabled())
		spin_lock(&cpa_lock);
	if (!base)
		return -ENOMEM;

	if (__split_large_page(cpa, kpte, address, base))
		__free_page(base);

	return 0;
}

static bool try_to_free_pte_page(pte_t *pte)
{
	int i;

	for (i = 0; i < PTRS_PER_PTE; i++)
		if (!pte_none(pte[i]))
			return false;

	free_page((unsigned long)pte);
	return true;
}

static bool try_to_free_pmd_page(pmd_t *pmd)
{
	int i;

	for (i = 0; i < PTRS_PER_PMD; i++)
		if (!pmd_none(pmd[i]))
			return false;

	free_page((unsigned long)pmd);
	return true;
}

static bool unmap_pte_range(pmd_t *pmd, unsigned long start, unsigned long end)
{
	pte_t *pte = pte_offset_kernel(pmd, start);

	while (start < end) {
		set_pte(pte, __pte(0));

		start += PAGE_SIZE;
		pte++;
	}

	if (try_to_free_pte_page((pte_t *)pmd_page_vaddr(*pmd))) {
		pmd_clear(pmd);
		return true;
	}
	return false;
}

static void __unmap_pmd_range(pud_t *pud, pmd_t *pmd,
			      unsigned long start, unsigned long end)
{
	if (unmap_pte_range(pmd, start, end))
		if (try_to_free_pmd_page((pmd_t *)pud_page_vaddr(*pud)))
			pud_clear(pud);
}

static void unmap_pmd_range(pud_t *pud, unsigned long start, unsigned long end)
{
	pmd_t *pmd = pmd_offset(pud, start);

	/*
	 * Not on a 2MB page boundary?
	 */
	if (start & (PMD_SIZE - 1)) {
		unsigned long next_page = (start + PMD_SIZE) & PMD_MASK;
		unsigned long pre_end = min_t(unsigned long, end, next_page);

		__unmap_pmd_range(pud, pmd, start, pre_end);

		start = pre_end;
		pmd++;
	}

	/*
	 * Try to unmap in 2M chunks.
	 */
	while (end - start >= PMD_SIZE) {
		if (pmd_large(*pmd))
			pmd_clear(pmd);
		else
			__unmap_pmd_range(pud, pmd, start, start + PMD_SIZE);

		start += PMD_SIZE;
		pmd++;
	}

	/*
	 * 4K leftovers?
	 */
	if (start < end)
		return __unmap_pmd_range(pud, pmd, start, end);

	/*
	 * Try again to free the PMD page if haven't succeeded above.
	 */
	if (!pud_none(*pud))
		if (try_to_free_pmd_page((pmd_t *)pud_page_vaddr(*pud)))
			pud_clear(pud);
}

static void unmap_pud_range(p4d_t *p4d, unsigned long start, unsigned long end)
{
	pud_t *pud = pud_offset(p4d, start);

	/*
	 * Not on a GB page boundary?
	 */
	if (start & (PUD_SIZE - 1)) {
		unsigned long next_page = (start + PUD_SIZE) & PUD_MASK;
		unsigned long pre_end	= min_t(unsigned long, end, next_page);

		unmap_pmd_range(pud, start, pre_end);

		start = pre_end;
		pud++;
	}

	/*
	 * Try to unmap in 1G chunks?
	 */
	while (end - start >= PUD_SIZE) {

		if (pud_large(*pud))
			pud_clear(pud);
		else
			unmap_pmd_range(pud, start, start + PUD_SIZE);

		start += PUD_SIZE;
		pud++;
	}

	/*
	 * 2M leftovers?
	 */
	if (start < end)
		unmap_pmd_range(pud, start, end);

	/*
	 * No need to try to free the PUD page because we'll free it in
	 * populate_pgd's error path
	 */
}

static int alloc_pte_page(pmd_t *pmd)
{
	pte_t *pte = (pte_t *)get_zeroed_page(GFP_KERNEL);
	if (!pte)
		return -1;

	set_pmd(pmd, __pmd(__pa(pte) | _KERNPG_TABLE));
	return 0;
}

static int alloc_pmd_page(pud_t *pud)
{
	pmd_t *pmd = (pmd_t *)get_zeroed_page(GFP_KERNEL);
	if (!pmd)
		return -1;

	set_pud(pud, __pud(__pa(pmd) | _KERNPG_TABLE));
	return 0;
}

static void populate_pte(struct cpa_data *cpa,
			 unsigned long start, unsigned long end,
			 unsigned num_pages, pmd_t *pmd, pgprot_t pgprot)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, start);

	pgprot = pgprot_clear_protnone_bits(pgprot);

	while (num_pages-- && start < end) {
		set_pte(pte, pfn_pte(cpa->pfn, pgprot));

		start	 += PAGE_SIZE;
		cpa->pfn++;
		pte++;
	}
}

static long populate_pmd(struct cpa_data *cpa,
			 unsigned long start, unsigned long end,
			 unsigned num_pages, pud_t *pud, pgprot_t pgprot)
{
	long cur_pages = 0;
	pmd_t *pmd;
	pgprot_t pmd_pgprot;

	/*
	 * Not on a 2M boundary?
	 */
	if (start & (PMD_SIZE - 1)) {
		unsigned long pre_end = start + (num_pages << PAGE_SHIFT);
		unsigned long next_page = (start + PMD_SIZE) & PMD_MASK;

		pre_end   = min_t(unsigned long, pre_end, next_page);
		cur_pages = (pre_end - start) >> PAGE_SHIFT;
		cur_pages = min_t(unsigned int, num_pages, cur_pages);

		/*
		 * Need a PTE page?
		 */
		pmd = pmd_offset(pud, start);
		if (pmd_none(*pmd))
			if (alloc_pte_page(pmd))
				return -1;

		populate_pte(cpa, start, pre_end, cur_pages, pmd, pgprot);

		start = pre_end;
	}

	/*
	 * We mapped them all?
	 */
	if (num_pages == cur_pages)
		return cur_pages;

	pmd_pgprot = pgprot_4k_2_large(pgprot);

	while (end - start >= PMD_SIZE) {

		/*
		 * We cannot use a 1G page so allocate a PMD page if needed.
		 */
		if (pud_none(*pud))
			if (alloc_pmd_page(pud))
				return -1;

		pmd = pmd_offset(pud, start);

		set_pmd(pmd, pmd_mkhuge(pfn_pmd(cpa->pfn,
					canon_pgprot(pmd_pgprot))));

		start	  += PMD_SIZE;
		cpa->pfn  += PMD_SIZE >> PAGE_SHIFT;
		cur_pages += PMD_SIZE >> PAGE_SHIFT;
	}

	/*
	 * Map trailing 4K pages.
	 */
	if (start < end) {
		pmd = pmd_offset(pud, start);
		if (pmd_none(*pmd))
			if (alloc_pte_page(pmd))
				return -1;

		populate_pte(cpa, start, end, num_pages - cur_pages,
			     pmd, pgprot);
	}
	return num_pages;
}

static int populate_pud(struct cpa_data *cpa, unsigned long start, p4d_t *p4d,
			pgprot_t pgprot)
{
	pud_t *pud;
	unsigned long end;
	long cur_pages = 0;
	pgprot_t pud_pgprot;

	end = start + (cpa->numpages << PAGE_SHIFT);

	/*
	 * Not on a Gb page boundary? => map everything up to it with
	 * smaller pages.
	 */
	if (start & (PUD_SIZE - 1)) {
		unsigned long pre_end;
		unsigned long next_page = (start + PUD_SIZE) & PUD_MASK;

		pre_end   = min_t(unsigned long, end, next_page);
		cur_pages = (pre_end - start) >> PAGE_SHIFT;
		cur_pages = min_t(int, (int)cpa->numpages, cur_pages);

		pud = pud_offset(p4d, start);

		/*
		 * Need a PMD page?
		 */
		if (pud_none(*pud))
			if (alloc_pmd_page(pud))
				return -1;

		cur_pages = populate_pmd(cpa, start, pre_end, cur_pages,
					 pud, pgprot);
		if (cur_pages < 0)
			return cur_pages;

		start = pre_end;
	}

	/* We mapped them all? */
	if (cpa->numpages == cur_pages)
		return cur_pages;

	pud = pud_offset(p4d, start);
	pud_pgprot = pgprot_4k_2_large(pgprot);

	/*
	 * Map everything starting from the Gb boundary, possibly with 1G pages
	 */
	while (boot_cpu_has(X86_FEATURE_GBPAGES) && end - start >= PUD_SIZE) {
		set_pud(pud, pud_mkhuge(pfn_pud(cpa->pfn,
				   canon_pgprot(pud_pgprot))));

		start	  += PUD_SIZE;
		cpa->pfn  += PUD_SIZE >> PAGE_SHIFT;
		cur_pages += PUD_SIZE >> PAGE_SHIFT;
		pud++;
	}

	/* Map trailing leftover */
	if (start < end) {
		long tmp;

		pud = pud_offset(p4d, start);
		if (pud_none(*pud))
			if (alloc_pmd_page(pud))
				return -1;

		tmp = populate_pmd(cpa, start, end, cpa->numpages - cur_pages,
				   pud, pgprot);
		if (tmp < 0)
			return cur_pages;

		cur_pages += tmp;
	}
	return cur_pages;
}

/*
 * Restrictions for kernel page table do not necessarily apply when mapping in
 * an alternate PGD.
 */
static int populate_pgd(struct cpa_data *cpa, unsigned long addr)
{
	pgprot_t pgprot = __pgprot(_KERNPG_TABLE);
	pud_t *pud = NULL;	/* shut up gcc */
	p4d_t *p4d;
	pgd_t *pgd_entry;
	long ret;

	pgd_entry = cpa->pgd + pgd_index(addr);

	if (pgd_none(*pgd_entry)) {
		p4d = (p4d_t *)get_zeroed_page(GFP_KERNEL);
		if (!p4d)
			return -1;

		set_pgd(pgd_entry, __pgd(__pa(p4d) | _KERNPG_TABLE));
	}

	/*
	 * Allocate a PUD page and hand it down for mapping.
	 */
	p4d = p4d_offset(pgd_entry, addr);
	if (p4d_none(*p4d)) {
		pud = (pud_t *)get_zeroed_page(GFP_KERNEL);
		if (!pud)
			return -1;

		set_p4d(p4d, __p4d(__pa(pud) | _KERNPG_TABLE));
	}

	pgprot_val(pgprot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(pgprot) |=  pgprot_val(cpa->mask_set);

	ret = populate_pud(cpa, addr, p4d, pgprot);
	if (ret < 0) {
		/*
		 * Leave the PUD page in place in case some other CPU or thread
		 * already found it, but remove any useless entries we just
		 * added to it.
		 */
		unmap_pud_range(p4d, addr,
				addr + (cpa->numpages << PAGE_SHIFT));
		return ret;
	}

	cpa->numpages = ret;
	return 0;
}

static int __cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr,
			       int primary)
{
	if (cpa->pgd) {
		/*
		 * Right now, we only execute this code path when mapping
		 * the EFI virtual memory map regions, no other users
		 * provide a ->pgd value. This may change in the future.
		 */
		return populate_pgd(cpa, vaddr);
	}

	/*
	 * Ignore all non primary paths.
	 */
	if (!primary) {
		cpa->numpages = 1;
		return 0;
	}

	/*
	 * Ignore the NULL PTE for kernel identity mapping, as it is expected
	 * to have holes.
	 * Also set numpages to '1' indicating that we processed cpa req for
	 * one virtual address page and its pfn. TBD: numpages can be set based
	 * on the initial value and the level returned by lookup_address().
	 */
	if (within(vaddr, PAGE_OFFSET,
		   PAGE_OFFSET + (max_pfn_mapped << PAGE_SHIFT))) {
		cpa->numpages = 1;
		cpa->pfn = __pa(vaddr) >> PAGE_SHIFT;
		return 0;

	} else if (__cpa_pfn_in_highmap(cpa->pfn)) {
		/* Faults in the highmap are OK, so do not warn: */
		return -EFAULT;
	} else {
		WARN(1, KERN_WARNING "CPA: called for zero pte. "
			"vaddr = %lx cpa->vaddr = %lx\n", vaddr,
			*cpa->vaddr);

		return -EFAULT;
	}
}

static int __change_page_attr(struct cpa_data *cpa, int primary)
{
	unsigned long address;
	int do_split, err;
	unsigned int level;
	pte_t *kpte, old_pte;

	if (cpa->flags & CPA_PAGES_ARRAY) {
		struct page *page = cpa->pages[cpa->curpage];
		if (unlikely(PageHighMem(page)))
			return 0;
		address = (unsigned long)page_address(page);
	} else if (cpa->flags & CPA_ARRAY)
		address = cpa->vaddr[cpa->curpage];
	else
		address = *cpa->vaddr;
	//long repeat_iter=0; // debug
repeat:
	//repeat_iter++;
	kpte = _lookup_address_cpa(cpa, address, &level);
	if (!kpte){
		//printk(KERN_INFO "kpte is zero. repeat_iter: %ld\n", repeat_iter); //debug
		return __cpa_process_fault(cpa, address, primary);
	}//debug pair with brace

	old_pte = *kpte;
	if (pte_none(old_pte)){
		//printk(KERN_INFO "pte none for old pte. repeat_iter: %ld\n", repeat_iter); //debug
		return __cpa_process_fault(cpa, address, primary);
	}

	if (level == PG_LEVEL_4K) {
		pte_t new_pte;
		pgprot_t new_prot = pte_pgprot(old_pte);
		unsigned long pfn = pte_pfn(old_pte);

		pgprot_val(new_prot) &= ~pgprot_val(cpa->mask_clr);
		pgprot_val(new_prot) |= pgprot_val(cpa->mask_set);

		cpa_inc_4k_install();
		new_prot = static_protections(new_prot, address, pfn, 1,
					      CPA_PROTECT);

		new_prot = pgprot_clear_protnone_bits(new_prot);

		/*
		 * We need to keep the pfn from the existing PTE,
		 * after all we're only going to change it's attributes
		 * not the memory it points to
		 */
		new_pte = pfn_pte(pfn, new_prot);
		cpa->pfn = pfn;
		/*
		 * Do we really change anything ?
		 */
		if (pte_val(old_pte) != pte_val(new_pte)) {
			set_pte_atomic(kpte, new_pte);
			cpa->flags |= CPA_FLUSHTLB;
		}
		cpa->numpages = 1;
		return 0;
	}

	/*
	 * Check, whether we can keep the large page intact
	 * and just change the pte:
	 */
	do_split = should_split_large_page(kpte, address, cpa);
	/*
	 * When the range fits into the existing large page,
	 * return. cp->numpages and cpa->tlbflush have been updated in
	 * try_large_page:
	 */
	if (do_split <= 0){
		//printk(KERN_INFO "do_split is %d. repeat_iter: %ld\n", do_split, repeat_iter);// debug
		return do_split;
	} //debug
		

	/*
	 * We have to split the large page:
	 */
	err = split_large_page(cpa, kpte, address);
	if (!err)
		goto repeat;

	return err;
}


static int __change_page_attr_set_clr(struct cpa_data *cpa, int checkalias);

static int cpa_process_alias(struct cpa_data *cpa)
{
	struct cpa_data alias_cpa;
	unsigned long laddr = (unsigned long)__va(cpa->pfn << PAGE_SHIFT);
	unsigned long vaddr;
	int ret;

	if (!pfn_range_is_mapped(cpa->pfn, cpa->pfn + 1))
		return 0;

	/*
	 * No need to redo, when the primary call touched the direct
	 * mapping already:
	 */
	if (cpa->flags & CPA_PAGES_ARRAY) {
		struct page *page = cpa->pages[cpa->curpage];
		if (unlikely(PageHighMem(page)))
			return 0;
		vaddr = (unsigned long)page_address(page);
	} else if (cpa->flags & CPA_ARRAY)
		vaddr = cpa->vaddr[cpa->curpage];
	else
		vaddr = *cpa->vaddr;

	if (!(within(vaddr, PAGE_OFFSET,
		    PAGE_OFFSET + (max_pfn_mapped << PAGE_SHIFT)))) {

		alias_cpa = *cpa;
		alias_cpa.vaddr = &laddr;
		alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY);

		ret = __change_page_attr_set_clr(&alias_cpa, 0);
		if (ret)
			return ret;
	}

#ifdef CONFIG_X86_64
	/*
	 * If the primary call didn't touch the high mapping already
	 * and the physical address is inside the kernel map, we need
	 * to touch the high mapped kernel as well:
	 */
	if (!within(vaddr, (unsigned long)_text, _brk_end) &&
	    __cpa_pfn_in_highmap(cpa->pfn)) {
		unsigned long temp_cpa_vaddr = (cpa->pfn << PAGE_SHIFT) +
					       __START_KERNEL_map - phys_base;
		alias_cpa = *cpa;
		alias_cpa.vaddr = &temp_cpa_vaddr;
		alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY);

		/*
		 * The high mapping range is imprecise, so ignore the
		 * return value.
		 */
		__change_page_attr_set_clr(&alias_cpa, 0);
	}
#endif

	return 0;
}

static int __change_page_attr_set_clr(struct cpa_data *cpa, int checkalias)
{
	unsigned long numpages = cpa->numpages;
	int ret;

	while (numpages) {
		/*
		 * Store the remaining nr of pages for the large page
		 * preservation check.
		 */
		cpa->numpages = numpages;
		/* for array changes, we can't use large page */
		if (cpa->flags & (CPA_ARRAY | CPA_PAGES_ARRAY))
			cpa->numpages = 1;

		if (!debug_pagealloc_enabled())
			spin_lock(&cpa_lock);
		//printk(KERN_INFO "Now enter into cpa phase\n");
		ret = __change_page_attr(cpa, checkalias);
		if (!debug_pagealloc_enabled())
			spin_unlock(&cpa_lock);
		if (ret){
			//printk(KERN_INFO "There's something happening at cpa phase.\n ret: %d, numpages left: %ld\n", ret, numpages);
			return ret;
		}
		//	return ret;

		if (checkalias) {
			ret = cpa_process_alias(cpa);
			//printk(KERN_INFO "Alias occurs\n");
			if (ret)
				return ret;
		}

		/*
		 * Adjust the number of pages with the result of the
		 * CPA operation. Either a large page has been
		 * preserved or a single page update happened.
		 */
		BUG_ON(cpa->numpages > numpages || !cpa->numpages);
		numpages -= cpa->numpages;
		if (cpa->flags & (CPA_PAGES_ARRAY | CPA_ARRAY))
			cpa->curpage++;
		else
			*cpa->vaddr += cpa->numpages * PAGE_SIZE;

	}
	return 0;
}


/*
 * Machine check recovery code needs to change cache mode of poisoned
 * pages to UC to avoid speculative access logging another error. But
 * passing the address of the 1:1 mapping to set_memory_uc() is a fine
 * way to encourage a speculative access. So we cheat and flip the top
 * bit of the address. This works fine for the code that updates the
 * page tables. But at the end of the process we need to flush the cache
 * and the non-canonical address causes a #GP fault when used by the
 * CLFLUSH instruction.
 *
 * But in the common case we already have a canonical address. This code
 * will fix the top bit if needed and is a no-op otherwise.
 */
static inline unsigned long make_addr_canonical_again(unsigned long addr)
{
#ifdef CONFIG_X86_64
	return (long)(addr << 1) >> 1;
#else
	return addr;
#endif
}


static int change_page_attr_set_clr(unsigned long *addr, int numpages,
				    pgprot_t mask_set, pgprot_t mask_clr,
				    int force_split, int in_flag,
				    struct page **pages)
{
	struct cpa_data cpa;
	int ret, cache, checkalias;
	unsigned long baddr = 0;

	memset(&cpa, 0, sizeof(cpa));

	/*
	 * Check, if we are requested to set a not supported
	 * feature.  Clearing non-supported features is OK.
	 */
	mask_set = canon_pgprot(mask_set);
	int feature_support_flag=!pgprot_val(mask_set) && !pgprot_val(mask_clr) && !force_split;
	//printk(KERN_INFO "feature_support_flag: %d\n", feature_support_flag);
	if (feature_support_flag)
	//if (!pgprot_val(mask_set) && !pgprot_val(mask_clr) && !force_split)
		return 0;

	/* Ensure we are PAGE_SIZE aligned */
	if (in_flag & CPA_ARRAY) {
		int i;
		for (i = 0; i < numpages; i++) {
			if (addr[i] & ~PAGE_MASK) {
				addr[i] &= PAGE_MASK;
				WARN_ON_ONCE(1);
			}
		}
	} else if (!(in_flag & CPA_PAGES_ARRAY)) {
		/*
		 * in_flag of CPA_PAGES_ARRAY implies it is aligned.
		 * No need to cehck in that case
		 */
		if (*addr & ~PAGE_MASK) {
			*addr &= PAGE_MASK;
			/*
			 * People should not be passing in unaligned addresses:
			 */
			WARN_ON_ONCE(1);
		}
		/*
		 * Save address for cache flush. *addr is modified in the call
		 * to __change_page_attr_set_clr() below.
		 */
		baddr = make_addr_canonical_again(*addr);
	}

	/* Must avoid aliasing mappings in the highmem code */
	kmap_flush_unused();

	vm_unmap_aliases();

	cpa.vaddr = addr;
	cpa.pages = pages;
	cpa.numpages = numpages;
	cpa.mask_set = mask_set;
	cpa.mask_clr = mask_clr;
	cpa.flags = 0;
	cpa.curpage = 0;
	cpa.force_split = force_split;

	if (in_flag & (CPA_ARRAY | CPA_PAGES_ARRAY))
		cpa.flags |= in_flag;

	/* No alias checking for _NX bit modifications */
	checkalias = (pgprot_val(mask_set) | pgprot_val(mask_clr)) != _PAGE_NX;
	/* Has caller explicitly disabled alias checking? */
	if (in_flag & CPA_NO_CHECK_ALIAS)
		checkalias = 0;
	//printk(KERN_INFO "Enter into real page attribute change\n");
	ret = __change_page_attr_set_clr(&cpa, checkalias);

	/*
	 * Check whether we really changed something:
	 */
	if (!(cpa.flags & CPA_FLUSHTLB))
		goto out;

	/*
	 * No need to flush, when we did not set any of the caching
	 * attributes:
	 */
	cache = !!pgprot2cachemode(mask_set);

	/*
	 * On error; flush everything to be sure.
	 */
	if (ret) {
		cpa_flush_all(cache);
		goto out;
	}

	if (cpa.flags & (CPA_PAGES_ARRAY | CPA_ARRAY)) {
		cpa_flush_array(baddr, addr, numpages, cache,
				cpa.flags, pages);
	} else {
		cpa_flush_range(baddr, numpages, cache);
	}

out:
	return ret;
}

static inline int change_page_attr_set(unsigned long *addr, int numpages,
				       pgprot_t mask, int array)
{
	return change_page_attr_set_clr(addr, numpages, mask, __pgprot(0), 0,
		(array ? CPA_ARRAY : 0), NULL);
}

static inline int change_page_attr_clear(unsigned long *addr, int numpages,
					 pgprot_t mask, int array)
{
	return change_page_attr_set_clr(addr, numpages, __pgprot(0), mask, 0,
		(array ? CPA_ARRAY : 0), NULL);
}

static inline int cpa_set_pages_array(struct page **pages, int numpages,
				       pgprot_t mask)
{
	return change_page_attr_set_clr(NULL, numpages, mask, __pgprot(0), 0,
		CPA_PAGES_ARRAY, pages);
}

static inline int cpa_clear_pages_array(struct page **pages, int numpages,
					 pgprot_t mask)
{
	return change_page_attr_set_clr(NULL, numpages, __pgprot(0), mask, 0,
		CPA_PAGES_ARRAY, pages);
}

int _set_memory_uc_PAT_user(unsigned long addr, int numpages)
{
	/*
	 * for now UC MINUS. see comments in ioremap_nocache()
	 * If you really need strong UC use ioremap_uc(), but note
	 * that you cannot override IO areas with set_memory_*() as
	 * these helpers cannot work with IO memory.
	 */
	return change_page_attr_set(&addr, numpages,
				    cachemode2pgprot(_PAGE_CACHE_MODE_UC_MINUS),
				    0);
}

int set_memory_uc_PAT_user(unsigned long addr, int numpages)
{
	int ret;

	/*
	 * for now UC MINUS. see comments in ioremap_nocache()
	 */
	ret = reserve_memtype(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
			      _PAGE_CACHE_MODE_UC_MINUS, NULL);
	if (ret)
		goto out_err;

	ret = _set_memory_uc_PAT_user(addr, numpages);
	if (ret)
		goto out_free;

	return 0;

out_free:
	free_memtype(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);
out_err:
	return ret;
}
EXPORT_SYMBOL(set_memory_uc_PAT_user);

int _set_memory_wc_PAT_user(unsigned long addr, int numpages)
{
	int ret;
	unsigned long addr_copy = addr;

	ret = change_page_attr_set(&addr, numpages,
				   cachemode2pgprot(_PAGE_CACHE_MODE_UC_MINUS),
				   0);
	if (!ret) {
		ret = change_page_attr_set_clr(&addr_copy, numpages,
					       cachemode2pgprot(
						_PAGE_CACHE_MODE_WC),
					       __pgprot(_PAGE_CACHE_MASK),
					       0, 0, NULL);
	}
	return ret;
}

int set_memory_wc_PAT_user(unsigned long addr, int numpages)
{
	int ret;

	ret = reserve_memtype(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
		_PAGE_CACHE_MODE_WC, NULL);
	if (ret)
		return ret;
	//printk(KERN_INFO "Reserve at set_memory_wc passed\n");
	ret = _set_memory_wc_PAT_user(addr, numpages);
	if (ret)
		free_memtype(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);
	//printk(KERN_INFO "Freed by set_memory_wc occurred\n");
	return ret;
}
EXPORT_SYMBOL(set_memory_wc_PAT_user);

int _set_memory_wt_PAT_user(unsigned long addr, int numpages)
{
	return change_page_attr_set(&addr, numpages,
				    cachemode2pgprot(_PAGE_CACHE_MODE_WT), 0);
}

int set_memory_wt_PAT_user(unsigned long addr, int numpages)
{
	int ret;

	ret = reserve_memtype(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
			      _PAGE_CACHE_MODE_WT, NULL);
	if (ret)
		return ret;

	ret = _set_memory_wt_PAT_user(addr, numpages);
	if (ret)
		free_memtype(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);

	return ret;
}
EXPORT_SYMBOL_GPL(set_memory_wt_PAT_user);

int _set_memory_wb_PAT_user(unsigned long addr, int numpages)
{
	/* WB cache mode is hard wired to all cache attribute bits being 0 */
	return change_page_attr_clear(&addr, numpages,
				      __pgprot(_PAGE_CACHE_MASK), 0);
}

int set_memory_wb_PAT_user(unsigned long addr, int numpages)
{
	int ret;

	ret = _set_memory_wb_PAT_user(addr, numpages);
	if (ret)
		return ret;
	//printk(KERN_INFO "Freed by set_memory_wb occurred\n");
	free_memtype(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);
	return 0;
}
EXPORT_SYMBOL(set_memory_wb_PAT_user);


/*
kernel_map_pages_in_pgd 
is pre-implemented in pageattr.c 
*/
/*struct cpa_data {
	unsigned long	*vaddr;
	pgd_t		*pgd;
	pgprot_t	mask_set;
	pgprot_t	mask_clr;
	unsigned long	numpages;
	int		flags;
	unsigned long	pfn;
	unsigned	force_split		: 1,
			force_static_prot	: 1;
	int		curpage;
	struct page	**pages;
};*/
//Default page is write back..
#define PAGE_BIT_4KB (12)
#define PAGE_SIZE_4KB (4096)
#define PMD_OFFSET_IN_ADDRESS (21)
#define PMD_OFFSET_SIZE (1048576*2)
#define NUMBER_OF_PTE_IN_ONE_PAGE (512)
#define BITS_OF_PTE_FOR_ONE_PAGE (9)

pmd_t *pmd_to_be_change(unsigned long address)
{
	pgd_t *pgd; 
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd=pgd_offset(current->mm, address);
	if(pgd_none(*pgd)){
		//printk(KERN_INFO "address %lx's pgd doesn't exist\n", address);
		return NULL;
	}
	p4d=p4d_offset(pgd, address);
	if(p4d_none(*p4d)){
		//printk(KERN_INFO "address %lx's p4d doesn't exist\n", address);
		return NULL;
	}
	pud=pud_offset(p4d, address);
	if(pud_none(*pud)){
		//printk(KERN_INFO "address %lx's pud doesn't exist\n", address);
		return NULL;
	}
	pmd=pmd_offset(pud, address);
	if(pmd_none(*pmd)){
		//printk(KERN_INFO "address %lx's pmd doesn't exist\n", address);
		return NULL;
	}
	return pmd;
	//return pte_offset_kernel(pmd, address);
}
//dokyu: This is obtained by sudo rmdsr 0x277
#define PTE_ENTRY_SIZE 8
//This masks represent for PAT, PCD, PWT bits..
//PAT|PCD|PWT represents the corresponding cache mode
//0: WB, 1: WC, 2: UC-, 3: UC
//4: WB, 5: WP, 6: UC-, 7: WT
#define PAT_WB 0UL
#define PAT_WC 8UL
#define PAT_UC_minus 16UL
#define PAT_UC 24UL
#define PAT_WP 136UL
#define PAT_WT 152UL
struct eff_cpa_data {
	/*unsigned long	*vaddr;
	pgd_t		*pgd;
	pgprot_t	mask_set;
	pgprot_t	mask_clr;
	unsigned long	numpages;
	int		flags;
	unsigned long	pfn;
	unsigned	force_split		: 1,
			force_static_prot	: 1;
	int		curpage;
	struct page	**pages;*/

	unsigned long addr;
	unsigned long numpages;

	//In directory(pmd) data
	unsigned long start_in_dir;
	unsigned long end_in_dir;
};
static void clflush_cache_range_opt_dk(void *vaddr, unsigned int size)
{
	const unsigned long clflush_size = boot_cpu_data.x86_clflush_size;
	void *p = (void *)((unsigned long)vaddr & ~(clflush_size - 1));
	void *vend = vaddr + size;
	//printk("addr: %lx\n", vaddr);
	if (p >= vend)
		return;
	//printk("checking the limit is end\n");
	for (; p < vend; p += clflush_size){
		//printk("Flush the address p: %lx\n", p);
		clflushopt(p);
	}
	//printk("every cache line is flushed\n");
}
void cpa_in_pmd(pmd_t* pmd, struct eff_cpa_data cpa_info, unsigned long PAT_option){
	pmdval_t pmd_address=pte_offset_kernel(pmd, 0);
	
	//printk("pmd address: %lx", pmd_address);
	//printk("finding address: %lx\n", cpa_info.addr);
	
	//printk("pmd address: %lx", pmd_address);
	pteval_t* pte_array=(pteval_t* ) pmd_address;
	unsigned long and_mask=0x98;
	and_mask=~and_mask;
	unsigned long i;
	unsigned long start_in_pmd=cpa_info.start_in_dir;
	unsigned long end_in_pmd=cpa_info.end_in_dir;
	//mb();
	for(i=start_in_pmd; i<=end_in_pmd; i++){
		//clflush should occur before setting..
		pteval_t pte_val_i=pte_array[i];
		unsigned long current_page_addr=((cpa_info.addr)&(~(PMD_OFFSET_SIZE-1)))+i*PAGE_SIZE_4KB;
		//printk("current page address: %lx\n", current_page_addr);
		if (pte_val_i & _PAGE_PRESENT){
			//printk("page present with its pte: %lx\n", pte_val_i);
			/*clflush_cache_range_opt_dk((void *)current_page_addr, PAGE_SIZE_4KB);
			//printk("flushed the cache line\n");*/
		}
		else{
			//printk("No page present\n");
			struct vm_area_struct* vma = find_vma(current->mm, current_page_addr);
			//printk("Found vma\n");
			handle_mm_fault(vma, current_page_addr, FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE | FAULT_FLAG_WRITE);
			//printk("Handle mm fault\n");
		}
		//printk("clflush or fault end\n");
		//printk("Previous pte value is %lx\n", pte_val_i);
		pte_array[i]=(pte_val_i&and_mask)+PAT_option;
		//printk("Success for masking to %lx\n", pte_array[i]);
	}
	//mb();
}

int cpa_base_dk(unsigned long addr, unsigned long numpages, unsigned long PAT_option){
	//0. flush every cacheline
	/*printk(KERN_INFO "check the access begin\n");
	access_ok(VERIFY_READ, addr, numpages*PAGE_SIZE_4KB);
	printk(KERN_INFO "check the access end\n");*/
	/*printk(KERN_INFO "clflush begins\n");
	//dump_stack();
	clflush_cache_range(addr, numpages*PAGE_SIZE_4KB);
	printk(KERN_INFO "clflush is done\n");*/
	// if addr is not aligned, return -1;
	struct eff_cpa_data cpa_info;
	cpa_info.addr=addr;
	cpa_info.numpages=numpages;

	if((addr&(PAGE_SIZE_4KB-1))!=0){
		//printk(KERN_INFO "Invalid alignment\n");
		return -1;
	}
	else{
		//printk(KERN_INFO "alignment check is done\n");
	}
	long page_number = (addr >> PAGE_BIT_4KB);
	cpa_info.start_in_dir = page_number - (((page_number) >> BITS_OF_PTE_FOR_ONE_PAGE) << BITS_OF_PTE_FOR_ONE_PAGE);
	cpa_info.end_in_dir=(numpages<(NUMBER_OF_PTE_IN_ONE_PAGE-1-cpa_info.start_in_dir))? (cpa_info.start_in_dir+numpages-1): (NUMBER_OF_PTE_IN_ONE_PAGE-1);
	
	unsigned long PAT_option_valid_checker=0x98;
	PAT_option_valid_checker=~PAT_option_valid_checker;
	if((PAT_option&PAT_option_valid_checker)!=0){
		//printk(KERN_INFO "Invalid PAT_option\n");
		return -1;
	}
	else{
		//printk(KERN_INFO "PAT option check is done\n");
	}

	while(cpa_info.numpages>0){
		//printk("addr: %lx\n", cpa_info.addr);
		//printk("numpages left: %lx\n", cpa_info.numpages);
		//printk("start: %lx, end: %lx\n", cpa_info.start_in_dir, cpa_info.end_in_dir);
		//1. find the pmd
		//printk("Find pmd begin\n");
		pmd_t* pmd=pmd_to_be_change(cpa_info.addr);
		//printk("Find pmd done\n");
		//2. change attribute
		//printk("cpa begins\n");
		cpa_in_pmd(pmd,cpa_info, PAT_option);
		//printk("cpa done\n");
		//3. update TLB
		cpa_info.addr=cpa_info.addr+((cpa_info.end_in_dir-cpa_info.start_in_dir+1)<<PAGE_BIT_4KB);
		cpa_info.numpages-=(cpa_info.end_in_dir-cpa_info.start_in_dir+1);
		cpa_info.start_in_dir=0;
		cpa_info.end_in_dir=(cpa_info.numpages<NUMBER_OF_PTE_IN_ONE_PAGE-1)? cpa_info.numpages-1: (NUMBER_OF_PTE_IN_ONE_PAGE-1);
	}
	//update TLB
	//printk("flush tlb begins\n");
	flush_tlb_mm_range(current->mm, addr, addr+numpages*PAGE_SIZE_4KB, PAGE_BIT_4KB, false);
	//printk("flush tlb ends\n");
	//flush_tlb_range(current->mm->mmap, addr, addr+numpages*PAGE_SIZE_4KB);
	return 0;
}
EXPORT_SYMBOL(cpa_base_dk);





//functionality check

/*
int pmd_print(unsigned long addr, int numpages){
	// if addr is not aligned, return -1;

	struct cpa_data cpa_info;
	cpa_info.vaddr=addr;
	cpa_info.numpages=numpages;

	if(addr&(PAGE_SIZE_4KB-1)!=0){
		return -1;
	}
	long page_number = (addr >> PAGE_BIT_4KB);
	long base_offset_pmd = page_number - (((page_number) >> BITS_OF_PTE_FOR_ONE_PAGE) << BITS_OF_PTE_FOR_ONE_PAGE);
	int first=1;

	while(cpa_info.numpages>0){
		pmd_t* pmd=pmd_to_be_changed(cpa_info.vaddr);
		printk(KERN_INFO "Address %lx 's pmd: %lx\n", addr, pmd_val(*pmd));
		//1. find the pmd
		//2. flush every cacheline
		//3. change attribute
		//4. update TLB

		if(cpa_info.numpages< NUMBER_OF_PTE_IN_ONE_PAGE-base_offset_pmd){
			cpa_info.numpages=0;
		}
		else{
			
		}
		addr+=PAGE_SIZE_4KB;
		base_offset_pmd=(base_offset_pmd+1)%NUMBER_OF_PTE_IN_ONE_PAGE;
		numpages--;
	}
	return 0;
	//1. flush every cache range

	//2. 


}*/
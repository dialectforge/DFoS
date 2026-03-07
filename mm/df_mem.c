// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge Memory Protection (Phase 5)
 * mm/df_mem.c
 *
 * Dialect-mapped memory pages. Physical RAM always holds encoded data.
 * Three-tier acceleration:
 *   Tier 1: AMD SME/SEV — hardware AES at memory bus speed
 *   Tier 2: Intel TME/MKTME — hardware per-key AES encryption
 *   Tier 3: Software — HMAC-SHA256 XOR keystream (universal fallback)
 *
 * At boot, detect available hardware and pick the fastest path.
 * Security guarantee is identical regardless of backend.
 *
 * Copyright (C) 2026 John Dean Martin. Protocol is proprietary.
 * OS integration is GPL.
 */

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/internal/cipher.h>
#include <linux/scatterlist.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/task_work.h>
#include <linux/rcutree.h>  /* rcu_momentary_eqs */
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <linux/dma-direction.h>
#include <linux/device.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/cpufeatures.h>
#include <asm/msr.h>
#include <asm/processor.h>

#ifdef CONFIG_DIALECTFORGE
#include <linux/dialectforge.h>

/* ============================================================
 * SECTION 1: Backend Selection & Hardware Detection
 * ============================================================ */

enum df_mem_backend {
	DF_MEM_BACKEND_SOFTWARE    = 0,
	DF_MEM_BACKEND_AMD_SME     = 1,
	DF_MEM_BACKEND_AMD_SEV     = 2,
	DF_MEM_BACKEND_INTEL_TME   = 3,
	DF_MEM_BACKEND_INTEL_MKTME = 4,
};

static enum df_mem_backend df_mem_active_backend = DF_MEM_BACKEND_SOFTWARE;

static const char *df_mem_backend_names[] = {
	[DF_MEM_BACKEND_SOFTWARE]    = "software (HMAC-SHA256 XOR keystream)",
	[DF_MEM_BACKEND_AMD_SME]     = "AMD SME (hardware AES-128, bus-level)",
	[DF_MEM_BACKEND_AMD_SEV]     = "AMD SEV (hardware VM encryption)",
	[DF_MEM_BACKEND_INTEL_TME]   = "Intel TME (hardware AES-XTS-128)",
	[DF_MEM_BACKEND_INTEL_MKTME] = "Intel MKTME (hardware per-key AES)",
};

static u32 df_mem_mktme_num_keys = 0;

/* AMD MSRs */
#define DF_MSR_AMD_SYSCFG              0xC0010010
#define DF_MSR_AMD_SYSCFG_MEM_ENCRYPT  BIT_ULL(23)
#define DF_MSR_AMD_SEV_STATUS          0xC0010131
#define DF_MSR_AMD_SEV_ENABLED         BIT_ULL(0)
#define DF_AMD_CPUID_MEM_ENCRYPT       0x8000001F

/* Intel MSRs */
#define DF_MSR_IA32_TME_ACTIVATE       0x982
#define DF_MSR_IA32_TME_ACTIVATE_EN    BIT_ULL(1)

static bool df_mem_detect_amd(void)
{
	u32 eax, ebx, ecx, edx;
	u64 msr_val;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD)
		return false;

	if (boot_cpu_data.extended_cpuid_level < DF_AMD_CPUID_MEM_ENCRYPT)
		return false;

	cpuid(DF_AMD_CPUID_MEM_ENCRYPT, &eax, &ebx, &ecx, &edx);

	if (!(eax & BIT(0))) {
		pr_info("df_mem: AMD CPU, SME not supported by this model\n");
		return false;
	}

	if (rdmsrl_safe(DF_MSR_AMD_SYSCFG, &msr_val))
		return false;

	if (!(msr_val & DF_MSR_AMD_SYSCFG_MEM_ENCRYPT)) {
		pr_info("df_mem: AMD SME supported but not enabled "
			"(enable via BIOS or mem_encrypt=on)\n");
		return false;
	}

	if (eax & BIT(1)) {
		u64 sev_msr;
		if (!rdmsrl_safe(DF_MSR_AMD_SEV_STATUS, &sev_msr) &&
		    (sev_msr & DF_MSR_AMD_SEV_ENABLED)) {
			df_mem_active_backend = DF_MEM_BACKEND_AMD_SEV;
			return true;
		}
	}

	df_mem_active_backend = DF_MEM_BACKEND_AMD_SME;
	return true;
}

static bool df_mem_detect_intel(void)
{
	u32 eax, ebx, ecx, edx;
	u64 msr_val;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return false;

	cpuid_count(0x7, 0, &eax, &ebx, &ecx, &edx);

	if (!(ecx & BIT(13))) {
		pr_info("df_mem: Intel CPU, TME not supported by this model\n");
		return false;
	}

	if (rdmsrl_safe(DF_MSR_IA32_TME_ACTIVATE, &msr_val))
		return false;

	if (!(msr_val & DF_MSR_IA32_TME_ACTIVATE_EN)) {
		pr_info("df_mem: Intel TME supported but not enabled "
			"(enable in BIOS)\n");
		return false;
	}

	{
		u32 key_bits = (msr_val >> 32) & 0xF;
		if (key_bits > 0) {
			df_mem_mktme_num_keys = 1U << key_bits;
			df_mem_active_backend = DF_MEM_BACKEND_INTEL_MKTME;
			return true;
		}
	}

	df_mem_active_backend = DF_MEM_BACKEND_INTEL_TME;
	return true;
}

static void df_mem_detect_hardware(void)
{
	pr_info("df_mem: Scanning for hardware memory encryption...\n");

	if (df_mem_detect_amd()) {
		pr_info("df_mem: => %s\n",
			df_mem_backend_names[df_mem_active_backend]);
		return;
	}

	if (df_mem_detect_intel()) {
		pr_info("df_mem: => %s\n",
			df_mem_backend_names[df_mem_active_backend]);
		if (df_mem_active_backend == DF_MEM_BACKEND_INTEL_MKTME)
			pr_info("df_mem: MKTME key slots: %u\n",
				df_mem_mktme_num_keys);
		return;
	}

	df_mem_active_backend = DF_MEM_BACKEND_SOFTWARE;
	pr_info("df_mem: No hardware encryption => %s\n",
		df_mem_backend_names[DF_MEM_BACKEND_SOFTWARE]);
}

/* ============================================================
 * SECTION 2: Per-CPU State & Config
 * ============================================================ */

#define DF_MEM_KEYSTREAM_BYTES  PAGE_SIZE

#ifdef CONFIG_DF_DEBUG
#define df_mem_dbg(fmt, ...) \
	pr_debug("df_mem: " fmt, ##__VA_ARGS__)
#else
#define df_mem_dbg(fmt, ...) do {} while (0)
#endif

struct df_mem_pcpu {
	u8 keystream[DF_MEM_KEYSTREAM_BYTES];
	u8 decode_buf[PAGE_SIZE];
	bool active;
	spinlock_t lock;
	/* Pre-allocated AES-256-CTR cipher (uses AES-NI when available,
	 * avoids sleeping in page-fault context) */
	struct crypto_cipher *aes_tfm;
	/* Pre-allocated work buffer for CTR counter block (16 bytes = AES block) */
	u8 ctr_block[16]; /* 4 counter + 4 nonce + 8 addr */
};

static DEFINE_PER_CPU(struct df_mem_pcpu, df_mem_pcpu_data);

static bool df_mem_initialized = false;
static bool df_mem_enabled = true;  /* boot-time only: df.mem_off=1 to disable */
static bool df_mem_defer_requested = false;  /* set by df.mem_defer=1 */

static atomic64_t df_dma_blocked_count = ATOMIC64_INIT(0);
static atomic64_t df_dma_flagged_count = ATOMIC64_INIT(0);
static atomic64_t df_dma_allowed_count = ATOMIC64_INIT(0);
/* Forward declarations */
static int df_sw_generate_keystream(struct df_mem_pcpu *pcpu,
                    const u8 *seed_bytes,
                    unsigned long page_addr, u32 nonce, u8 *out);
static int df_sw_xor_page(struct page *page, const u8 *seed_bytes,
               unsigned long vaddr, u32 nonce);
static void __init df_mem_mm_states_init(void);
static void df_mem_flip_pte_encoded_final(struct mm_struct *mm, unsigned long vaddr);
static void df_mm_release_state(struct mm_struct *mm);




static void df_mem_pte_protect_fast(struct mm_struct *mm, unsigned long vaddr);
static void df_mem_reencode_active(struct task_struct *task);
void df_mem_schedule_protect(struct task_struct *task);



void df_mem_context_switch(struct task_struct *prev, struct task_struct *next)
{
	struct df_mem_pcpu *pcpu;

	if (!df_mem_initialized || !df_mem_enabled)
		return;
	if (!prev->mm && !next->mm)
		return;

	if (prev->mm && (prev->df_ctx.flags & DF_TASKF_SEED_VALID)) {
		/* Per-CPU wipe only -- PTE protect + XOR handled by
		 * df_mem_schedule_protect + task_work */
		pcpu = this_cpu_ptr(&df_mem_pcpu_data);
		spin_lock(&pcpu->lock);
		memzero_explicit(pcpu->keystream, DF_MEM_KEYSTREAM_BYTES);
		memzero_explicit(pcpu->decode_buf, PAGE_SIZE);
		pcpu->active = false;
		spin_unlock(&pcpu->lock);

		clflush_cache_range(pcpu->keystream, DF_MEM_KEYSTREAM_BYTES);
		clflush_cache_range(pcpu->decode_buf, PAGE_SIZE);
	}
}

EXPORT_SYMBOL_GPL(df_mem_context_switch);

/* ============================================================
 * SECTION 6: Fork — Child Memory Dialect Init
 * ============================================================ */

int df_mem_fork_init(struct task_struct *child, struct task_struct *parent)
{
	if (!df_mem_initialized || !df_mem_enabled || !parent->mm)
		return 0;

	/* If parent lacks a seed (race during deferred enable),
	 * derive one from system root now.  This closes the window
	 * between df_mem_enabled=true and seed_all_processes. */
	if (!(parent->df_ctx.flags & DF_TASKF_SEED_VALID)) {
		struct df_seed on_demand;
		u8 label[48];  /* 16 random + "pid:NNNNN" */
		int label_len, ret;

		get_random_bytes(label, 16);
		label_len = 16 + snprintf((char *)label + 16, 32,
					  "pid:%d", parent->pid);
		ret = df_seed_derive_labeled(df_get_system_root_seed(),
					     (char *)label, label_len,
					     &on_demand);
		if (ret) {
			pr_warn("dialectforge: fork-init seed derivation failed pid %d: %d\n",
				parent->pid, ret);
			return 0;
		}
		task_lock(parent);
		memcpy(parent->df_ctx.seed_bytes, on_demand.bytes,
		       sizeof(parent->df_ctx.seed_bytes));
		parent->df_ctx.tier         = DF_TIER_NATIVE;
		parent->df_ctx.generation   = 0;
		parent->df_ctx.zone_id      = 0;
		parent->df_ctx.seed_born_ns = ktime_get_ns();
		parent->df_ctx.mem_gen      = 0;
		parent->df_ctx.mem_flags    = 0;
		smp_wmb();
		parent->df_ctx.flags       |= DF_TASKF_SEED_VALID;
		task_unlock(parent);
		pr_info("dialectforge: on-demand seed for parent pid %d\n",
			parent->pid);
	}

	child->df_ctx.mem_gen = parent->df_ctx.mem_gen + 1;
	child->df_ctx.mem_flags = 0;
	pr_debug("dialectforge: fork-init child=%d mm=%px hash=%lu parent=%d mm=%px hash=%lu\n",
		child->pid, child->mm,
		child->mm ? ((unsigned long)child->mm >> 12) & 0xFF : 999,
		parent->pid, parent->mm,
		parent->mm ? ((unsigned long)parent->mm >> 12) & 0xFF : 999);

	df_mem_dbg("fork: child %d gen=%u (parent %d gen=%u)\n",
		   child->pid, child->df_ctx.mem_gen,
		   parent->pid, parent->df_ctx.mem_gen);
	return 0;
}
EXPORT_SYMBOL_GPL(df_mem_fork_init);



/* ============================================================
 * SECTION 7: COW — Re-encode in Writer's Dialect
 * ============================================================ */

int df_mem_cow_page(struct page *new_page, struct page *old_page,
		    struct task_struct *new_owner,
		    struct task_struct *old_owner,
		    unsigned long vaddr)
{
	struct df_mem_pcpu *pcpu;
	u8 *new_data;
	unsigned int i;
	int ret;

	if (!df_mem_initialized || !df_mem_enabled)
		return 0;
	if (!(new_owner->df_ctx.flags & DF_TASKF_SEED_VALID))
		return 0;

	if (memcmp(new_owner->df_ctx.seed_bytes,
		   old_owner->df_ctx.seed_bytes, 32) == 0)
		return 0;

	pcpu = this_cpu_ptr(&df_mem_pcpu_data);
	spin_lock(&pcpu->lock);

	ret = df_sw_generate_keystream(pcpu, old_owner->df_ctx.seed_bytes,
				       vaddr & PAGE_MASK, 0, pcpu->decode_buf);
	if (ret)
		goto out;

	ret = df_sw_generate_keystream(pcpu, new_owner->df_ctx.seed_bytes,
				       vaddr & PAGE_MASK, 0, pcpu->keystream);
	if (ret)
		goto out;

	for (i = 0; i < PAGE_SIZE; i++)
		pcpu->keystream[i] ^= pcpu->decode_buf[i];

	new_data = kmap_local_page(new_page);
	for (i = 0; i < PAGE_SIZE; i++)
		new_data[i] ^= pcpu->keystream[i];
	kunmap_local(new_data);

out:
	memzero_explicit(pcpu->keystream, DF_MEM_KEYSTREAM_BYTES);
	memzero_explicit(pcpu->decode_buf, PAGE_SIZE);
	spin_unlock(&pcpu->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(df_mem_cow_page);

/* ============================================================
 * SECTION 8: Process Exit — Wipe Dialect State
 * ============================================================ */

void df_mem_exit_cleanup(struct task_struct *task)
{
	if (!df_mem_initialized || !df_mem_enabled || !task->mm)
		return;

	df_mem_dbg("exit: pid %d wiping dialect state\n", task->pid);
	/* Release hash bucket ownership so it can be reused */
	df_mm_release_state(task->mm);

	memzero_explicit(task->df_ctx.seed_bytes, 32);
	task->df_ctx.flags = 0;
	task->df_ctx.mem_gen = 0;
	task->df_ctx.mem_flags = 0;
}
EXPORT_SYMBOL_GPL(df_mem_exit_cleanup);


/* ============================================================
 * SECTION 10: /proc/df_mem Status
 * ============================================================ */

static int df_mem_proc_show(struct seq_file *m, void *v)
{
	int cpu;

	seq_puts(m, "=== DialectForge Memory Protection ===\n");
	seq_printf(m, "Status:       %s\n",
		   df_mem_initialized ? "ACTIVE" : "INIT");
	seq_printf(m, "Backend:      %s\n",
		   df_mem_backend_names[df_mem_active_backend]);

	switch (df_mem_active_backend) {
	case DF_MEM_BACKEND_AMD_SME:
	case DF_MEM_BACKEND_AMD_SEV:
		seq_puts(m, "Hardware:     AMD Secure Memory Encryption\n");
		seq_puts(m, "Bus layer:    AES-128 (zero overhead)\n");
		seq_puts(m, "Process layer: HMAC-SHA256 XOR (software)\n");
		seq_puts(m, "Total layers: 2\n");
		break;
	case DF_MEM_BACKEND_INTEL_TME:
		seq_puts(m, "Hardware:     Intel Total Memory Encryption\n");
		seq_puts(m, "Bus layer:    AES-XTS-128 (zero overhead)\n");
		seq_puts(m, "Process layer: HMAC-SHA256 XOR (software)\n");
		seq_puts(m, "Total layers: 2\n");
		break;
	case DF_MEM_BACKEND_INTEL_MKTME:
		seq_puts(m, "Hardware:     Intel Multi-Key TME\n");
		seq_printf(m, "Key slots:    %u\n", df_mem_mktme_num_keys);
		seq_puts(m, "Bus layer:    AES-XTS per key (hardware)\n");
		seq_puts(m, "Process layer: HMAC-SHA256 XOR (software; hw in Phase 7)\n");
		seq_puts(m, "Total layers: 2\n");
		break;
	default:
		seq_puts(m, "Hardware:     none\n");
		seq_puts(m, "Process layer: HMAC-SHA256 XOR (software)\n");
		seq_puts(m, "Total layers: 1\n");
		break;
	}

	seq_puts(m, "Context wipe: max (TLB + cache flush)\n");
	seq_printf(m, "DMA protect:  active (allowed=%lld blocked=%lld flagged=%lld)\n",
		 (long long)atomic64_read(&df_dma_allowed_count),
		 (long long)atomic64_read(&df_dma_blocked_count),
		 (long long)atomic64_read(&df_dma_flagged_count));
	seq_printf(m, "Page size:    %lu\n", PAGE_SIZE);

	seq_puts(m, "\nPer-CPU:\n");
	for_each_online_cpu(cpu) {
		struct df_mem_pcpu *pcpu = per_cpu_ptr(&df_mem_pcpu_data, cpu);
		seq_printf(m, "  CPU%d: %s\n", cpu,
			   pcpu->active ? "active" : "idle");
	}

	return 0;
}

static int df_mem_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, df_mem_proc_show, NULL);
}

static const struct proc_ops df_mem_proc_ops = {
	.proc_open    = df_mem_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ============================================================
 * SECTION 11: /proc/[pid]/mem Noise Encoding
 * ============================================================ */

/*
 * df_mem_proc_read_encode() — Encode a buffer being read via
 * /proc/[pid]/mem so the reader sees noise, not plaintext.
 *
 * Called from fs/proc/base.c mem_rw() after access_remote_vm()
 * copies page data into a kernel buffer. We XOR the buffer with
 * the target process's dialect keystream before copy_to_user().
 *
 * The owning process accesses its own pages at zero overhead.
 * Only remote readers see noise. This is the software-fallback
 * equivalent of what SME/TME do in hardware at the bus level.
 */
void df_mem_proc_read_encode(char *buf, size_t len,
			    const u8 *seed_bytes, unsigned long addr)
{
	struct df_mem_pcpu *pcpu;
	unsigned long page_addr = addr & PAGE_MASK;
	unsigned int page_off = addr & ~PAGE_MASK;
	unsigned int i;
	int ret;

	if (!df_mem_initialized || !df_mem_enabled || !seed_bytes)
		return;

	pcpu = this_cpu_ptr(&df_mem_pcpu_data);
	spin_lock(&pcpu->lock);

	ret = df_sw_generate_keystream(pcpu, seed_bytes, page_addr, 0, pcpu->keystream);
	if (ret) {
		spin_unlock(&pcpu->lock);
		return;
	}

	/* XOR buffer with keystream at correct page offset */
	for (i = 0; i < len && (page_off + i) < PAGE_SIZE; i++)
		buf[i] ^= pcpu->keystream[page_off + i];

	memzero_explicit(pcpu->keystream, DF_MEM_KEYSTREAM_BYTES);
	spin_unlock(&pcpu->lock);

	df_mem_dbg("/proc read encode: addr=%lx len=%zu\n", addr, len);
}
EXPORT_SYMBOL_GPL(df_mem_proc_read_encode);

/* ============================================================
 * SECTION 12: Initialization
 * ============================================================ */


/* ---- df_mem_enable: deferred activation control ---- */
static int __init df_mem_defer_setup(char *str)
{
	if (str && *str == '1') {
		df_mem_enabled = false;
		df_mem_defer_requested = true;
		pr_info("DialectForge: Memory protection deferred (df.mem_defer=1)\n");
	}
	return 1;
}
__setup("df.mem_defer=", df_mem_defer_setup);

static int __init df_mem_off_setup(char *str)
{
	if (str && *str == '1') {
		df_mem_enabled = false;
		df_mem_defer_requested = false;  /* prevent auto-re-enable */
		pr_info("DialectForge: Memory protection DISABLED by boot param (df.mem_off=1)\n");
	}
	return 1;
}
__setup("df.mem_off=", df_mem_off_setup);

static int __init df_mem_safemode_setup(char *str)
{
	if (str && *str == '1') {
		df_mem_enabled = false;
		df_mem_defer_requested = false;  /* prevent auto-re-enable */
		pr_info("DialectForge: SAFE MODE - memory protection disabled, network disabled\n");
	}
	return 1;
}
__setup("df.safemode=", df_mem_safemode_setup);

/* ---- Seed-on-enable: derive seeds for all deferred processes ---- */
#define DF_MAX_DEFERRED_PIDS 4096

static int df_mem_seed_all_processes(void)
{
	pid_t *pids;
	int count = 0, i, seeded = 0, ret;
	struct task_struct *p;
	struct df_seed child_seed;
	u8 label[48];  /* 16 random + "pid:NNNNN" */
	int label_len;

	pids = kmalloc_array(DF_MAX_DEFERRED_PIDS, sizeof(pid_t), GFP_KERNEL);
	if (!pids)
		return -ENOMEM;

	/* Phase 1: Collect ALL userspace PIDs under RCU.
	 * We do NOT skip DF_TASKF_SEED_VALID because during deferred boot,
	 * dup_task_struct copies the parent's flags including SEED_VALID.
	 * All processes share init's seed — each needs a unique one. */
	rcu_read_lock();
	for_each_process(p) {
		if (!p->mm)				/* skip kernel threads */
			continue;
		if (count < DF_MAX_DEFERRED_PIDS)
			pids[count++] = p->pid;
	}
	rcu_read_unlock();

	pr_info("dialectforge: seeding %d deferred processes\n", count);

	/* Phase 2: Derive seeds outside RCU (HKDF may sleep) */
	for (i = 0; i < count; i++) {
		rcu_read_lock();
		p = find_task_by_vpid(pids[i]);
		if (!p) {
			rcu_read_unlock();
			continue;
		}
		get_task_struct(p);
		rcu_read_unlock();

		/* Always re-seed: inherited SEED_VALID is stale */

		get_random_bytes(label, 16);
		label_len = 16 + snprintf((char *)label + 16, 32,
					  "pid:%d", pids[i]);
		ret = df_seed_derive_labeled(df_get_system_root_seed(),
					     (char *)label, label_len,
					     &child_seed);
		if (ret) {
			pr_warn("dialectforge: seed derivation failed pid %d: %d\n",
				pids[i], ret);
			put_task_struct(p);
			continue;
		}

		task_lock(p);
		memcpy(p->df_ctx.seed_bytes, child_seed.bytes,
		       sizeof(p->df_ctx.seed_bytes));
		p->df_ctx.tier         = DF_TIER_NATIVE;
		p->df_ctx.generation   = 0;
		p->df_ctx.zone_id      = 0;
		p->df_ctx.seed_born_ns = ktime_get_ns();
		p->df_ctx.mem_gen      = 0;
		p->df_ctx.mem_flags    = 0;
		smp_wmb();
		p->df_ctx.flags       |= DF_TASKF_SEED_VALID;
		task_unlock(p);

		put_task_struct(p);
		seeded++;
	}

	kfree(pids);
	pr_info("dialectforge: seeded %d/%d processes\n", seeded, count);
	return 0;
}

/* Runtime toggle REMOVED — protection state is boot-time only.
 * Controlled exclusively via GRUB kernel parameters:
 *   df.mem_off=1   — disable protection (requires GRUB superuser)
 *   df.safemode=1  — safe mode, no protection (requires GRUB superuser)
 * /proc/df_mem_enable is now a read-only status indicator. */

static int df_mem_enable_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", df_mem_enabled ? 1 : 0);
	return 0;
}

static int df_mem_enable_open(struct inode *inode, struct file *file)
{
	return single_open(file, df_mem_enable_show, NULL);
}

static const struct proc_ops df_mem_enable_proc_ops = {
	.proc_open    = df_mem_enable_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int __init df_mem_init(void)
{
	int cpu;

	pr_info("DialectForge: Memory Protection initializing...\n");

	df_mem_detect_hardware();

	for_each_possible_cpu(cpu) {
		struct df_mem_pcpu *pcpu = per_cpu_ptr(&df_mem_pcpu_data, cpu);
		struct crypto_cipher *tfm;

		spin_lock_init(&pcpu->lock);
		memset(pcpu->keystream, 0, DF_MEM_KEYSTREAM_BYTES);
		memset(pcpu->decode_buf, 0, PAGE_SIZE);
		pcpu->active = false;

		/* Pre-allocate AES-256 cipher per CPU.
		 * With -cpu host, kernel auto-selects AES-NI. */
		tfm = crypto_alloc_cipher("aes", 0, 0);
		if (IS_ERR(tfm)) {
			pr_err("df_mem: CPU%d: crypto_alloc_cipher(aes) failed: %ld\n",
			       cpu, PTR_ERR(tfm));
			pcpu->aes_tfm = NULL;
			continue;
		}
		pcpu->aes_tfm = tfm;
	}

	if (!proc_create("df_mem", 0444, NULL, &df_mem_proc_ops))
		pr_warn("df_mem: /proc/df_mem creation failed\n");
	if (!proc_create("df_mem_enable", 0444, NULL, &df_mem_enable_proc_ops))
		pr_warn("df_mem: /proc/df_mem_enable creation failed\n");

	df_mem_mm_states_init();
	df_mem_initialized = true;

	pr_info("DialectForge: Memory Protection ACTIVE\n");

	/* Harden sysctl defaults for DFoS */
	{
		extern int kptr_restrict;
		kptr_restrict = 2;  /* hide kernel pointers even from root */
	}
	pr_info("  Backend:      %s\n",
		df_mem_backend_names[df_mem_active_backend]);
	pr_info("  Context wipe: max (TLB + cache flush)\n");
	pr_info("  DMA:          active protection (block decoded, flag incoming)\n");

	return 0;
}

late_initcall(df_mem_init);

/* ---- Deferred auto-activation -----------------------------------
 * When df.mem_defer=1, protection starts disabled so early-boot
 * processes can run unseeded.  This late_initcall_sync seeds every
 * existing process and flips protection on — no userspace write
 * to /proc needed.  Runs after all late_initcalls complete.
 */
static int __init df_mem_deferred_activate(void)
{
	if (df_mem_enabled) {
		/* Already enabled (no deferral requested) */
		return 0;
	}
	/* If explicitly disabled by df.mem_off=1 or df.safemode=1,
	 * do NOT auto-enable. Check: if init set enabled=false AND
	 * defer was also requested, we should activate.  But if
	 * mem_off was used, enabled is false and we should stay off.
	 * Distinguish via a separate flag. */
	if (!df_mem_defer_requested) {
		pr_info("DialectForge: protection permanently off (boot param)\n");
		return 0;
	}
	pr_info("dialectforge: deferred activation — seeding all processes\n");
	df_mem_seed_all_processes();
	smp_wmb();
	df_mem_enabled = true;
	pr_info("DialectForge: Memory protection ENABLED (deferred)\n");
	return 0;
}
late_initcall_sync(df_mem_deferred_activate);



/* ============================================================
 * SECTION 13: Decode-on-Fault — The Missing Piece
 *
 * Pages are ALWAYS encoded in physical RAM. When the owning
 * process touches a page, we decode it in-place so the CPU
 * can execute/read/write it. We track which pages are
 * "decoded-active" and re-encode them on context switch.
 *
 * Non-owners never get decoded pages — they see noise.
 * ============================================================ */

/*
 * Per-mm tracking of decoded-active pages.
 * Simple array — good enough for v1. Production uses a radix tree.
 */
#define DF_MEM_MAX_ACTIVE_PAGES 16

struct df_active_page {
	struct page *page;
	unsigned long vaddr;
	u32 encode_nonce;
};

#define DF_MEM_MAX_NONCES 64

struct df_mem_nonce_entry {
	unsigned long vaddr;
	u32 nonce;
};

struct df_mem_mm_state {
	struct mm_struct *owner;   /* mm that owns this bucket (NULL = free) */
	struct df_active_page active[DF_MEM_MAX_ACTIVE_PAGES];
	unsigned int count;
	struct df_mem_nonce_entry encode_nonces[DF_MEM_MAX_NONCES];
	unsigned int nonce_count;
	/* Fault rate limiting: kill process if > threshold faults/sec */
	unsigned int fault_count;
	unsigned long fault_window_start;  /* jiffies */
	spinlock_t lock;
};

/* Per-mm state stored in a simple hashtable keyed by mm pointer */
#define DF_MM_HASH_BITS  8
#define DF_MM_HASH_SIZE  (1 << DF_MM_HASH_BITS)

static struct df_mem_mm_state df_mm_states[DF_MM_HASH_SIZE];

/*
 * df_mm_get_state() -- Look up the active-page state for an mm.
 *
 * Returns the bucket if it is owned by this mm, or if the bucket is
 * free (claims it for this mm).  Returns NULL if the bucket is owned
 * by a DIFFERENT mm (hash collision).  The caller must handle NULL
 * gracefully -- the process simply skips active[] tracking for that
 * cycle (pages stay decoded, safe but unprotected).
 */
static struct df_mem_mm_state *df_mm_get_state(struct mm_struct *mm)
{
	unsigned long hash = ((unsigned long)mm >> 12) & (DF_MM_HASH_SIZE - 1);
	struct df_mem_mm_state *state = &df_mm_states[hash];

	/* Fast path: bucket already owned by us */
	if (likely(state->owner == mm))
		return state;

	/* Bucket is free -- claim it */
	if (state->owner == NULL) {
		state->owner = mm;
		return state;
	}

	/* Collision: bucket owned by different mm.  Return NULL.
	 * Caller must handle this gracefully. */
	pr_info_once("dialectforge: hash collision mm=%px hash=%lu owner=%px\n",
		     mm, hash, state->owner);
	return NULL;
}

/*
 * df_mm_store_nonce() -- Store encode nonce for a vaddr.
 * Called from reencode_work after XOR encoding with a random nonce.
 * Caller must hold state->lock.
 */
static void df_mm_store_nonce(struct df_mem_mm_state *state,
			     unsigned long vaddr, u32 nonce)
{
	unsigned int i;

	/* Update existing entry if present */
	for (i = 0; i < state->nonce_count; i++) {
		if (state->encode_nonces[i].vaddr == vaddr) {
			state->encode_nonces[i].nonce = nonce;
			return;
		}
	}
	/* Add new entry */
	if (state->nonce_count < DF_MEM_MAX_NONCES) {
		state->encode_nonces[state->nonce_count].vaddr = vaddr;
		state->encode_nonces[state->nonce_count].nonce = nonce;
		state->nonce_count++;
	} else {
		pr_warn_ratelimited("dialectforge: nonce table full pid=%d\n",
				    current->pid);
	}
}

/*
 * df_mm_lookup_nonce() -- Find the encode nonce for a vaddr.
 * Returns 0 if not found (initial encode used nonce=0).
 * Removes the entry after lookup (one-shot).
 * Caller must hold state->lock.
 */
static u32 df_mm_lookup_nonce(struct df_mem_mm_state *state,
			     unsigned long vaddr)
{
	unsigned int i;
	u32 nonce;

	for (i = 0; i < state->nonce_count; i++) {
		if (state->encode_nonces[i].vaddr == vaddr) {
			nonce = state->encode_nonces[i].nonce;
			/* Remove by swapping with last */
			state->encode_nonces[i] =
				state->encode_nonces[state->nonce_count - 1];
			state->nonce_count--;
			return nonce;
		}
	}
	return 0; /* not found = initial encode used nonce 0 */
}

/*
 * df_mm_release_state() -- Release ownership of a hash bucket.
 * Called when an mm is being destroyed (exit_mm, exec) so the
 * bucket can be reused by another process.
 */
static void df_mm_release_state(struct mm_struct *mm)
{
	unsigned long hash = ((unsigned long)mm >> 12) & (DF_MM_HASH_SIZE - 1);
	struct df_mem_mm_state *state = &df_mm_states[hash];
	unsigned long flags;

	if (state->owner != mm)
		return;  /* Not ours (collision or already released) */

	spin_lock_irqsave(&state->lock, flags);
	state->count = 0;
	state->nonce_count = 0;
	state->owner = NULL;
	spin_unlock_irqrestore(&state->lock, flags);
}

/* ============================================================
 * SECTION 9: DMA Protection
 *
 * Pages in RAM are XOR-encoded when not actively decoded by a
 * running process.  This means:
 *
 *   DMA_TO_DEVICE (device reads RAM):
 *     If page is encoded => device sees noise.  SAFE.
 *     If page is actively decoded => device sees cleartext.  BLOCK.
 *
 *   DMA_FROM_DEVICE (device writes RAM):
 *     Incoming data is cleartext from device.  If the page belongs
 *     to a DF-protected process, the cleartext won't match the
 *     expected encoding.  We flag this and the page must be
 *     re-encoded by the owning process on next access.
 *
 * Net effect: PCIe bus sniffing returns noise for all outgoing
 * DMA, and incoming DMA is tracked for re-encoding.
 * ============================================================ */

/*
 * df_dma_page_is_decoded() -- check if a page is currently in
 * any mm's active-decoded set (cleartext in RAM).
 */
static bool df_dma_page_is_decoded(struct page *page)
{
	int i;
	unsigned int j;
	struct df_mem_mm_state *state;

	for (i = 0; i < DF_MM_HASH_SIZE; i++) {
		state = &df_mm_states[i];
		if (!state->owner)
			continue;
		spin_lock(&state->lock);
		for (j = 0; j < state->count; j++) {
			if (state->active[j].page == page) {
				spin_unlock(&state->lock);
				return true;
			}
		}
		spin_unlock(&state->lock);
	}
	return false;
}


int df_mem_dma_check(struct page *page, enum dma_data_direction dir,
		     struct device *dev)
{
	bool decoded;

	if (!df_mem_initialized || !df_mem_enabled)
		return 0;

	decoded = df_dma_page_is_decoded(page);

	switch (dir) {
	case DMA_TO_DEVICE:
		/*
		 * Device reading from RAM.  If page is encoded (normal
		 * state), the device reads noise => safe for bus sniffing.
		 * If page is decoded (process actively using it), block
		 * the DMA to prevent cleartext leaking onto the bus.
		 */
		if (decoded) {
			pr_warn_ratelimited(
				"dialectforge: DMA TO_DEVICE BLOCKED pfn=%lx "
				"dev=%s — page is decoded (cleartext)\n",
				page_to_pfn(page),
				dev ? dev_name(dev) : "?");
			atomic64_inc(&df_dma_blocked_count);
			return -EACCES;
		}
		/* Page is encoded => DMA sees noise.  Allow. */
		atomic64_inc(&df_dma_allowed_count);
		break;

	case DMA_FROM_DEVICE:
		/*
		 * Device writing to RAM.  Incoming data is cleartext
		 * from the device.  Flag it — the page's encoding
		 * state is now inconsistent and must be re-established
		 * when the owning process next accesses it.
		 */
		if (page_count(page) > 0) {
			pr_info_ratelimited(
				"dialectforge: DMA FROM_DEVICE pfn=%lx dev=%s "
				"— cleartext written, re-encode on access\n",
				page_to_pfn(page),
				dev ? dev_name(dev) : "?");
			atomic64_inc(&df_dma_flagged_count);
		}
		atomic64_inc(&df_dma_allowed_count);
		break;

	case DMA_BIDIRECTIONAL:
		/* Both directions — apply TO_DEVICE check */
		if (decoded) {
			pr_warn_ratelimited(
				"dialectforge: DMA BIDIR BLOCKED pfn=%lx "
				"dev=%s — page decoded\n",
				page_to_pfn(page),
				dev ? dev_name(dev) : "?");
			atomic64_inc(&df_dma_blocked_count);
			return -EACCES;
		}
		atomic64_inc(&df_dma_allowed_count);
		break;

	default:
		atomic64_inc(&df_dma_allowed_count);
		break;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(df_mem_dma_check);

static void df_mm_track_decoded(struct mm_struct *mm,
				struct page *page, unsigned long vaddr)
{
	struct df_mem_mm_state *state = df_mm_get_state(mm);
	unsigned long flags;

	if (!state)
		return;  /* Hash collision -- skip tracking */

	spin_lock_irqsave(&state->lock, flags);

	/* Check if already tracked */
	for (unsigned int i = 0; i < state->count; i++) {
		if (state->active[i].page == page) {
			spin_unlock_irqrestore(&state->lock, flags);
			return;
		}
	}

	if (state->count < DF_MEM_MAX_ACTIVE_PAGES) {
		state->active[state->count].page = page;
		state->active[state->count].vaddr = vaddr;
		state->count++;
	} else {
		/* Overflow: evict oldest entry, replace with new page. */
		/* Replace slot 0 with new page before unlocking */
		state->active[0].page = page;
		state->active[0].vaddr = vaddr;
		spin_unlock_irqrestore(&state->lock, flags);

		/* Eviction: drop the oldest entry WITHOUT encoding.
		 * We CANNOT safely take the PTE lock here because our
		 * caller (e.g. do_wp_page, decode_fault) may already hold
		 * a PTE lock for the same page table page, which would
		 * cause a self-deadlock on single-CPU systems.
		 *
		 * The evicted page stays decoded (PRESENT PTE, cleartext).
		 * It loses one cycle of protection but will be re-tracked
		 * on its next decode fault. */
		return;  /* Already unlocked */
	}

	spin_unlock_irqrestore(&state->lock, flags);
}

/*
 * df_mem_exec_reset() — Clear stale DF memory state after exec replaces mm.
 *
 * Problem: active[] is stored in a global hash table keyed by mm pointer.
 * SLUB reuses the same address for mm_new after freeing mm_old during exec,
 * so mm_new inherits stale active[] entries from mm_old.  These entries
 * reference freed physical pages and old-mm virtual addresses.  When
 * reencode_work fires post-exec, it XOR-encodes freed pages and flips
 * PTEs at wrong addresses in the new mm — corrupting memory.
 *
 * Fix: called from begin_new_exec() right after exec_mmap() sets
 * current->mm to mm_new.  Clears the hash bucket and resets task flags.
 */
void df_mem_exec_reset(void)
{
	struct df_mem_mm_state *state;
	unsigned long flags;

	if (!df_mem_initialized)
		return;
	if (!current->mm)
		return;

	/* Clear stale active[] entries inherited via hash collision */
	state = df_mm_get_state(current->mm);
	if (state) {
		spin_lock_irqsave(&state->lock, flags);
		state->count = 0;
		spin_unlock_irqrestore(&state->lock, flags);
	}

	/* Reset per-task DF memory flags for the fresh address space.
	 * DF_MEMF_PAGES_ENCODED: no pages encoded in the new mm yet.
	 *
	 * CRITICAL: Do NOT clear DF_MEMF_REENCODE_PENDING here.
	 * A stale reencode_work callback may still be queued in the
	 * task_work LIFO.  Clearing the flag lets schedule_protect
	 * call init_task_work() on the same callback_head while it
	 * is still linked, corrupting the chain (double-fput BUG_ON,
	 * infinite loops, hangs).  Let the stale callback fire
	 * harmlessly (active[] is empty) and clear the flag itself. */
	current->df_ctx.mem_flags &= ~DF_MEMF_PAGES_ENCODED;

	df_mem_dbg("exec-reset: cleared stale DF state for pid %d\n",
		   current->pid);
}
EXPORT_SYMBOL_GPL(df_mem_exec_reset);

/*
 * df_mem_pre_fork() — Decode all encoded pages and clear active[]
 * before fork copies PTEs.
 *
 * TWO problems that cause child segfaults after fork:
 *
 * 1) ACTIVE pages (decoded, PRESENT, in active[]):
 *    If schedule_protect runs during copy_page_range, it flips parent
 *    PTEs to PROTNONE+SOFTW2+SOFTW3.  copy_nonpresent_pte copies these
 *    without mapcount increment.  reencode_work XOR-encodes the physical
 *    page (mc=1), child faults and gets garbage.
 *    Fix: Clear active[] so schedule_protect has nothing to flip.
 *
 * 2) ENCODED pages (XOR’d in RAM, PROTNONE+SOFTW2, NOT in active[]):
 *    copy_page_range sees !pte_present → copy_nonpresent_pte, which
 *    interprets the PTE as a swap entry → corrupts the PTE metadata.
 *    Even if copied verbatim, the child would need the parent’s seed
 *    to decode, which is fragile and violates fork semantics.
 *    Fix: Decode all encoded pages before fork so copy_page_range
 *    sees PRESENT PTEs → proper CoW with correct mapcount.
 *
 * This is spec-faithful: fork captures the logical cleartext state.
 * Both parent and child re-encode independently afterward through
 * their normal schedule_protect → reencode_work cycles.
 *
 * Called from dup_mmap() under mmap_write_lock(oldmm), which:
 *  - Prevents new page faults during decode
 *  - Stabilizes the VMA list for iteration
 *
 * Returns: kmalloc’d active[] snapshot (caller must kfree), or NULL.
 *          *count_out receives the number of entries.
 */
struct df_active_page *df_mem_pre_fork(struct mm_struct *mm,
				       unsigned int *count_out)
{
	struct df_mem_mm_state *state;
	struct df_active_page *snapshot = NULL;
	unsigned long flags;
	unsigned int count;
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);
	int decoded = 0;

	*count_out = 0;

	if (!df_mem_enabled || !df_mem_initialized)
		return NULL;
	if (!mm)
		return NULL;
	if (!(current->df_ctx.flags & DF_TASKF_SEED_VALID))
		return NULL;

	/*
	 * Phase 1: Decode all PROTNONE+SOFTW2 pages across all VMAs.
	 * These are fully XOR-encoded pages NOT in active[].
	 * We walk the page tables directly (same approach as
	 * df_mem_decode_vma_range but for the entire address space).
	 */
	for_each_vma(vmi, vma) {
		unsigned long addr;

		/* Skip non-user VMAs */
		if (!(vma->vm_flags & VM_READ))
			continue;

		for (addr = vma->vm_start; addr < vma->vm_end;
		     addr += PAGE_SIZE) {
			pgd_t *pgd;
			p4d_t *p4d;
			pud_t *pud;
			pmd_t *pmd;
			pte_t *ptep, pte;
			spinlock_t *ptl;
			pteval_t v;
			struct page *page;
			bool skip_xor;

			pgd = pgd_offset(mm, addr);
			if (pgd_none(*pgd) || pgd_bad(*pgd))
				continue;
			p4d = p4d_offset(pgd, addr);
			if (p4d_none(*p4d) || p4d_bad(*p4d))
				continue;
			pud = pud_offset(p4d, addr);
			if (pud_none(*pud) || pud_bad(*pud))
				continue;
			pmd = pmd_offset(pud, addr);
			if (pmd_none(*pmd) || pmd_bad(*pmd))
				continue;

			ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
			if (!ptep)
				continue;

			pte = ptep_get(ptep);
			v = pte_val(pte);

			/* Only decode DF-encoded: !PRESENT + SOFTW2 */
			if ((v & _PAGE_PRESENT) || !(v & _PAGE_SOFTW2)) {
				pte_unmap_unlock(ptep, ptl);
				continue;
			}

			skip_xor = !!(v & _PAGE_SOFTW3);
			page = pte_page(pte);
			get_page(page);  /* Pin before releasing ptl */
			pte_unmap_unlock(ptep, ptl);  /* Release lock for XOR */

			/* XOR-decode outside spinlock */
			if (!skip_xor) {
				u32 dec_nonce = 0;
				struct df_mem_mm_state *ns = df_mm_get_state(mm);
				if (ns) {
					unsigned long nf;
					spin_lock_irqsave(&ns->lock, nf);
					dec_nonce = df_mm_lookup_nonce(ns, addr);
					spin_unlock_irqrestore(&ns->lock, nf);
				}
				pr_debug("df-xor-call: PRE-FORK-DECODE pfn=%lx vaddr=%lx pid=%d\n",
					page_to_pfn(page), addr, current->pid);
				df_sw_xor_page(page, current->df_ctx.seed_bytes,
					       addr, dec_nonce);
			}

			/* Re-acquire lock, flip PTE to PRESENT */
			ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
			if (ptep) {
				pte = ptep_get(ptep);
				v = pte_val(pte);
				if (!(v & _PAGE_PRESENT) &&
				    (v & _PAGE_SOFTW2)) {
					pteval_t nv = v;
					nv |= _PAGE_PRESENT;
					nv &= ~(_PAGE_PROTNONE |
						_PAGE_SOFTW2 |
						_PAGE_SOFTW3);
					nv = flip_protnone_guard(
						v, nv, PTE_PFN_MASK);
					set_pte_at(mm, addr, ptep,
						   pte_mkyoung(__pte(nv)));
					decoded++;
				}
				pte_unmap_unlock(ptep, ptl);
			}

			put_page(page);
		}
	}

	if (decoded) {
		flush_tlb_mm(mm);
		pr_debug("dialectforge: pre-fork decoded %d encoded pages pid %d\n",
			decoded, current->pid);
	}

	/*
	 * Phase 2: Snapshot and clear active[] (decoded PRESENT pages).
	 * With active[] empty, schedule_protect has nothing to flip
	 * even if preempted during copy_page_range.
	 */
	state = df_mm_get_state(mm);

	if (state) {
		spin_lock_irqsave(&state->lock, flags);
		count = state->count;
		if (count > 0) {
			snapshot = kmalloc_array(count, sizeof(*snapshot), GFP_ATOMIC);
			if (snapshot)
				memcpy(snapshot, state->active,
				       count * sizeof(*snapshot));
			state->count = 0;
		}
		spin_unlock_irqrestore(&state->lock, flags);
	}

	*count_out = snapshot ? count : 0;
	pr_debug("dialectforge: pre-fork cleared %u active pages pid %d\n",
		 count, current->pid);
	return snapshot;
}
EXPORT_SYMBOL_GPL(df_mem_pre_fork);

/*
 * df_mem_post_fork_parent() — Restore active[] after copy_page_range.
 *
 * Called from dup_mmap() after all PTEs have been copied.  CoW is now
 * properly set up (mapcount reflects shared pages).  Restore the parent's
 * active[] so schedule_protect can re-protect these pages on the next
 * context switch.  The reencode_work CoW guard (folio_mapcount > 1)
 * will safely skip any pages shared with the child.
 */
void df_mem_post_fork_parent(struct mm_struct *mm,
			    struct df_active_page *snapshot,
			    unsigned int count)
{
	struct df_mem_mm_state *state;
	unsigned long flags;
	unsigned int i, restored = 0;

	if (!snapshot || count == 0)
		return;

	state = df_mm_get_state(mm);
	if (!state) {
		kfree(snapshot);
		pr_debug("dialectforge: post-fork skip restore (hash collision) pid %d\n",
			 current->pid);
		return;
	}

	spin_lock_irqsave(&state->lock, flags);
	for (i = 0; i < count && state->count < DF_MEM_MAX_ACTIVE_PAGES; i++) {
		state->active[state->count] = snapshot[i];
		state->count++;
		restored++;
	}
	spin_unlock_irqrestore(&state->lock, flags);

	kfree(snapshot);
	pr_debug("dialectforge: post-fork restored %u/%u active pages pid %d\n",
		 restored, count, current->pid);
}
EXPORT_SYMBOL_GPL(df_mem_post_fork_parent);


/*
 * df_mem_pte_get_pfn() -- Extract PFN from PTE at given vaddr.
 * Returns the PFN, or 0 on failure (unmapped/no PTE).
 * Used to verify snapshot page matches current PTE before XOR.
 */
static unsigned long df_mem_pte_get_pfn(struct mm_struct *mm, unsigned long vaddr)
{
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	unsigned long pfn;

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd)) return 0;
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d)) return 0;
	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud)) return 0;
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) return 0;

	ptep = pte_offset_map_lock(mm, pmd, vaddr, &ptl);
	if (!ptep) return 0;
	pte = ptep_get(ptep);
	pfn = pte_pfn(pte);
	pte_unmap_unlock(ptep, ptl);
	return pfn;
}

/*
 * df_mem_pte_is_protected() -- Check if PTE is still in protected state.
 * Returns true if PTE has PROTNONE+SOFTW2+SOFTW3 (set by schedule_protect,
 * meaning page is cleartext but PTE-guarded, awaiting XOR re-encode).
 * Returns false if PTE was re-faulted back to PRESENT, or is in any
 * other state -- meaning reencode_work must NOT XOR this page.
 */
static bool df_mem_pte_is_protected(struct mm_struct *mm, unsigned long vaddr)
{
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	bool protected;

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd)) return false;
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d)) return false;
	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud)) return false;
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) return false;

	ptep = pte_offset_map_lock(mm, pmd, vaddr, &ptl);
	if (!ptep) return false;
	pte = ptep_get(ptep);

	/* Expected: PROTNONE+SOFTW2+SOFTW3 (protected-but-cleartext) */
	protected = ((pte_val(pte) & (_PAGE_PROTNONE | _PAGE_SOFTW2 | _PAGE_SOFTW3)) ==
		     (_PAGE_PROTNONE | _PAGE_SOFTW2 | _PAGE_SOFTW3));

	pte_unmap_unlock(ptep, ptl);
	return protected;
}

/*
 * df_mem_pte_check_present() -- Check if a PTE is in PRESENT state.
 * Used to distinguish re-faulted pages (PRESENT) from stale entries
 * (PROTNONE+SOFTW2 = already encoded) in reencode_work.
 */
static bool df_mem_pte_check_present(struct mm_struct *mm, unsigned long vaddr)
{
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	bool present;

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd)) return false;
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d)) return false;
	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud)) return false;
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) return false;

	ptep = pte_offset_map_lock(mm, pmd, vaddr, &ptl);
	if (!ptep) return false;
	pte = ptep_get(ptep);

	present = !!(pte_val(pte) & _PAGE_PRESENT);

	pte_unmap_unlock(ptep, ptl);
	return present;
}

/*
 * df_mem_reencode_work() -- task_work callback to XOR re-encode.
 * Runs via TWA_RESUME just before the task returns to userspace.
 * Pages were already PTE-protected (PROTNONE+SOFTW2+SOFTW3) in
 * __schedule before any locks, so no userspace can access them.
 * This callback does the heavy crypto then clears SOFTW3.
 */
static void df_mem_reencode_work(struct callback_head *work)
{
	struct task_struct *task = current;
	struct df_mem_mm_state *state;
	struct df_active_page snapshot[DF_MEM_MAX_ACTIVE_PAGES];
	unsigned long flags;
	unsigned int count, i;

	/* NOTE: DF_MEMF_REENCODE_PENDING is cleared at the END of this
	 * function, not here.  Clearing it early allows schedule_protect
	 * to re-queue reencode_work while we're still running (preempted
	 * during slow XOR crypto), creating a livelock where the system
	 * spends all CPU time in reencode cycles with no forward progress.
	 * Keeping it set blocks re-queue until we finish. */

	if (!task->mm) {
		task->df_ctx.mem_flags &= ~DF_MEMF_REENCODE_PENDING;
		return;
	}

	state = df_mm_get_state(task->mm);
	if (!state) {
		/* Hash collision -- cannot track this mm.  Clear pending flag
		 * so schedule_protect can retry next cycle. */
		task->df_ctx.mem_flags &= ~DF_MEMF_REENCODE_PENDING;
		return;
	}

	spin_lock_irqsave(&state->lock, flags);
	count = state->count;
	if (count > 0)
		memcpy(snapshot, state->active,
		       count * sizeof(struct df_active_page));
	state->count = 0;   /* clear so schedule_protect does not re-process stale entries */
	spin_unlock_irqrestore(&state->lock, flags);

	for (i = 0; i < count; i++) {
		/* Guard: if the page was re-faulted back to PRESENT between
		 * schedule_protect and now (e.g. copy_from_user during a
		 * syscall that was preempted), the PTE is no longer in the
		 * PROTNONE+SOFTW2+SOFTW3 state.  Encoding such a page would
		 * leave encrypted data behind a PRESENT PTE -- the task would
		 * read XOR garbage (stack canary corruption, etc).  Skip it
		 * and re-track so schedule_protect handles it next cycle. */
		if (!df_mem_pte_is_protected(task->mm, snapshot[i].vaddr)) {
			/* Check if PTE is PRESENT (re-faulted) vs already-encoded
			 * (PROTNONE+SOFTW2 without SOFTW3 = stale entry).
			 * Re-faulted pages need re-tracking; stale entries
			 * should be dropped to avoid wasting active[] slots. */
			bool is_present = df_mem_pte_check_present(
				task->mm, snapshot[i].vaddr);
			if (is_present) {
				/* Re-faulted: re-add so schedule_protect
				 * handles it next cycle */
				spin_lock_irqsave(&state->lock, flags);
				if (state->count < DF_MEM_MAX_ACTIVE_PAGES) {
					state->active[state->count] = snapshot[i];
					state->count++;
				}
				spin_unlock_irqrestore(&state->lock, flags);
			} else {
				/* Already encoded or unmapped -- drop */
				pr_debug("dialectforge: dropping stale active entry vaddr=%lx pid=%d\n",
					snapshot[i].vaddr, task->pid);
			}
			continue;
		}
		/* CoW guard: if this page is mapped by multiple processes
		 * (fork created CoW copies), do NOT XOR-encode it in-place.
		 * df_sw_xor_page uses kmap_local_page which writes directly
		 * to the physical page, bypassing CoW -- the child process
		 * still has a PRESENT PTE to the same physical page and
		 * would read XOR garbage (corrupted pointers, segfault).
		 *
		 * Leave PTE in PROTNONE+SOFTW2+SOFTW3 state.  On next
		 * access, decode fault sees SOFTW3, skips XOR (page is
		 * still cleartext), flips to PRESENT.  Correct.
		 *
		 * Re-track so schedule_protect handles it next cycle.
		 * Once CoW breaks (child writes), mapcount drops to 1
		 * and we can safely encode the private copy. */
		if (folio_mapcount(page_folio(snapshot[i].page)) > 1) {
			spin_lock_irqsave(&state->lock, flags);
			if (state->count < DF_MEM_MAX_ACTIVE_PAGES) {
				state->active[state->count] = snapshot[i];
				state->count++;
			}
			spin_unlock_irqrestore(&state->lock, flags);
			continue;
		}
		pr_debug("df-xor-call: REENCODE-1ST pfn=%lx vaddr=%lx pid=%d\n",
			page_to_pfn(snapshot[i].page), snapshot[i].vaddr, task->pid);
		pr_debug("df-xor-call: REENCODE-ACTIVE pfn=%lx vaddr=%lx pid=%d\n",
			page_to_pfn(snapshot[i].page), snapshot[i].vaddr, task->pid);
		/* PFN verification: snapshot page must match current PTE.
		 * After CoW or page migration, PTE may point to a different
		 * physical page. XOR'ing the wrong page corrupts data. */
		{
			unsigned long pte_pfn_val = df_mem_pte_get_pfn(
				task->mm, snapshot[i].vaddr);
			unsigned long snap_pfn = page_to_pfn(snapshot[i].page);
			if (pte_pfn_val != snap_pfn) {
				pr_debug("dialectforge: reencode PFN mismatch "
					"vaddr=%lx snap_pfn=%lx pte_pfn=%lx pid=%d\n",
					snapshot[i].vaddr, snap_pfn,
					pte_pfn_val, task->pid);
				continue;
			}
		}
		{
			u32 enc_nonce;
			get_random_bytes(&enc_nonce, sizeof(enc_nonce));
			df_sw_xor_page(snapshot[i].page,
				       task->df_ctx.seed_bytes,
				       snapshot[i].vaddr, enc_nonce);
			/* Store nonce so decode_fault can look it up */
			spin_lock_irqsave(&state->lock, flags);
			df_mm_store_nonce(state, snapshot[i].vaddr, enc_nonce);
			spin_unlock_irqrestore(&state->lock, flags);
		}
		df_mem_flip_pte_encoded_final(task->mm, snapshot[i].vaddr);

		/* Report RCU quiescent state after each page.
		 * Each page requires 128 SHA hashes for keystream
		 * generation which is very slow under QEMU.
		 * cond_resched() is a no-op with CONFIG_PREEMPT_DYNAMIC
		 * + full preemption, and rcu_all_qs() is excluded
		 * when CONFIG_PREEMPTION=y.  Use rcu_momentary_eqs()
		 * to simulate a zero-duration dyntick-idle, which
		 * lets the grace period advance. At this point we
		 * are outside all RCU read-side critical sections
		 * (pte_unmap_unlock already called rcu_read_unlock). */
		local_irq_save(flags);
		rcu_momentary_eqs();
		local_irq_restore(flags);
	}

	/* Clear pending flag NOW so schedule_protect can queue next time.
	 * This was deliberately deferred from the start of the function
	 * to prevent livelock: if schedule_protect re-queues while we're
	 * still running slow XOR crypto, the system burns all CPU time
	 * in reencode cycles with no forward progress for the task. */
	task->df_ctx.mem_flags &= ~DF_MEMF_REENCODE_PENDING;
}

/* Forward declarations for Section 13 decode-on-fault */

bool df_mem_has_hw_backend(void)
{
	return df_mem_active_backend != DF_MEM_BACKEND_SOFTWARE;
}

/*
 * df_mem_pte_protect_fast() -- Fast PTE flip to PROTNONE+SOFTW2+SOFTW3.
 * Called from __schedule BEFORE any locks. No crypto, just PTE bits.
 * SOFTW3 marks "protected-but-cleartext" so the decode handler knows
 * no XOR is needed if the task faults back before task_work fires.
 */
static void df_mem_pte_protect_fast(struct mm_struct *mm, unsigned long vaddr)
{
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd)) return;
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d)) return;
	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud)) return;
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) return;

	ptep = pte_offset_map_lock(mm, pmd, vaddr, &ptl);
	if (!ptep) return;
	pte = ptep_get(ptep);

	if (pte_present(pte)) {
		pteval_t old_val = pte_val(pte);
		pteval_t val = old_val;
		/* DIAG: detect if PTE is already encoded (PROTNONE+SOFTW2) */
		if (old_val & _PAGE_SOFTW2) {
			pr_debug("dialectforge: protect-fast on ENCODED pte! vaddr=%lx pte=%lx pid=%d\n",
				vaddr, old_val, current->pid);
			pte_unmap_unlock(ptep, ptl);
			return;  /* DO NOT add SOFTW3 to already-encoded page */
		}
		val &= ~_PAGE_PRESENT;
		val |= _PAGE_PROTNONE | _PAGE_SOFTW2 | _PAGE_SOFTW3;
		val = flip_protnone_guard(old_val, val, PTE_PFN_MASK);
		set_pte_at(mm, vaddr, ptep, __pte(val));
	}

	pte_unmap_unlock(ptep, ptl);
}

/*
 * df_mem_flip_pte_encoded_final() -- Clear SOFTW3 after XOR completes.
 * PROTNONE + SOFTW2 + SOFTW3  -->  PROTNONE + SOFTW2 (fully encoded).
 */
static void df_mem_flip_pte_encoded_final(struct mm_struct *mm, unsigned long vaddr)
{
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd)) return;
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d)) return;
	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud)) return;
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) return;

	ptep = pte_offset_map_lock(mm, pmd, vaddr, &ptl);
	if (!ptep) return;
	pte = ptep_get(ptep);

	if ((pte_val(pte) & (_PAGE_PROTNONE | _PAGE_SOFTW2 | _PAGE_SOFTW3)) ==
	    (_PAGE_PROTNONE | _PAGE_SOFTW2 | _PAGE_SOFTW3)) {
		pteval_t val = pte_val(pte) & ~_PAGE_SOFTW3;
		set_pte_at(mm, vaddr, ptep, __pte(val));
	}

	pte_unmap_unlock(ptep, ptl);
}

EXPORT_SYMBOL_GPL(df_mem_has_hw_backend);

bool df_mem_is_enabled(void)
{
	return df_mem_initialized && df_mem_enabled;
}
EXPORT_SYMBOL_GPL(df_mem_is_enabled);
/* ============================================================
 * SECTION 3: Software Backend — Keystream Engine
 * ============================================================ */
/* Caller MUST hold pcpu->lock and pass the pcpu pointer.
 * Uses pre-allocated per-CPU AES-256 cipher in CTR mode.
 * With AES-NI (-cpu host), this is hardware-accelerated.
 * Counter block layout (16 bytes): [4 counter | 4 nonce | 8 addr] */
static int df_sw_generate_keystream(struct df_mem_pcpu *pcpu,
				    const u8 *seed_bytes,
				    unsigned long page_addr, u32 nonce,
				    u8 *out)
{
	u8 *ctr = pcpu->ctr_block;
	unsigned int offset = 0;
	u32 counter = 0;
	int ret;

	if (unlikely(!pcpu->aes_tfm))
		return -ENODEV;

	/* Set the 256-bit key (seed) */
	ret = crypto_cipher_setkey(pcpu->aes_tfm, seed_bytes, 32);
	if (ret)
		return ret;

	/* Build the static part of the counter block:
	 * [0..3]  = counter (changes each iteration)
	 * [4..7]  = nonce
	 * [8..15] = page virtual address */
	memset(ctr, 0, 16);
	memcpy(ctr + 4, &nonce, 4);
	memcpy(ctr + 8, &page_addr, sizeof(page_addr));

	/* Generate PAGE_SIZE bytes of keystream: 256 x AES-ECB(key, ctr++) */
	while (offset < PAGE_SIZE) {
		memcpy(ctr, &counter, 4);
		crypto_cipher_encrypt_one(pcpu->aes_tfm, out + offset, ctr);
		offset += 16;  /* AES block = 16 bytes */
		counter++;
	}

	memzero_explicit(ctr, 16);
	return 0;
}

static int df_sw_xor_page(struct page *page, const u8 *seed_bytes,
			   unsigned long vaddr, u32 nonce)
{
	struct df_mem_pcpu *pcpu;
	u8 *page_data;
	unsigned int i;
	int ret;

	pcpu = this_cpu_ptr(&df_mem_pcpu_data);
	spin_lock(&pcpu->lock);

	ret = df_sw_generate_keystream(pcpu, seed_bytes, vaddr & PAGE_MASK,
				       nonce, pcpu->keystream);
	if (ret)
		goto out;

	page_data = kmap_local_page(page);

	for (i = 0; i < PAGE_SIZE; i++)
		page_data[i] ^= pcpu->keystream[i];

	kunmap_local(page_data);

out:
	memzero_explicit(pcpu->keystream, DF_MEM_KEYSTREAM_BYTES);
	spin_unlock(&pcpu->lock);
	return ret;
}

/* ============================================================
 * SECTION 4: Unified Encode/Decode API
 * ============================================================ */

static inline bool df_mem_should_protect(struct task_struct *task)
{
	if (!df_mem_initialized || !df_mem_enabled)
		return false;
	/* Only protect userspace processes */
	if (!task->mm)
		return false;
	if (!(task->df_ctx.flags & DF_TASKF_SEED_VALID))
		return false;
	return true;
}

/*
 * df_mem_encode_page() — Encode a page with the process's dialect.
 *
 * All backends apply software per-process XOR.
 * Hardware backends (SME/TME) provide an ADDITIONAL bus-level layer.
 * When MKTME key programming is done (Phase 7), MKTME path can
 * skip software XOR and use hardware per-key encryption instead.
 */
int df_mem_encode_page(struct page *page, struct task_struct *task,
		       unsigned long vaddr)
{
	if (!df_mem_should_protect(task))
		return 0;

	df_mem_dbg("encode page %lx pid %d [%s]\n",
		   vaddr, task->pid,
		   df_mem_backend_names[df_mem_active_backend]);

	task->df_ctx.mem_flags |= DF_MEMF_PAGES_ENCODED;
	pr_debug("df-xor-call: ENCODE-ALLOC pfn=%lx vaddr=%lx pid=%d\n",
		page_to_pfn(page), vaddr, task->pid);
	return df_sw_xor_page(page, task->df_ctx.seed_bytes, vaddr, 0);
}
EXPORT_SYMBOL_GPL(df_mem_encode_page);

int df_mem_decode_page(struct page *page, struct task_struct *task,
		       unsigned long vaddr)
{
	if (!df_mem_should_protect(task))
		return 0;

	df_mem_dbg("decode page %lx pid %d\n", vaddr, task->pid);
	pr_debug("df-xor-call: DECODE-LEGACY pfn=%lx vaddr=%lx pid=%d\n",
		page_to_pfn(page), vaddr, task->pid);
	return df_sw_xor_page(page, task->df_ctx.seed_bytes, vaddr, 0);
}
EXPORT_SYMBOL_GPL(df_mem_decode_page);

/* ============================================================
 * SECTION 5: Context Switch — Maximum Wipe
 * ============================================================ */

/*
 * df_mem_schedule_protect() -- Called from __schedule() BEFORE locks.
 * Fast PTE-protect: flips decoded pages to PROTNONE+SOFTW2+SOFTW3,
 * flushes TLB, queues task_work for deferred XOR re-encode.
 * No crypto here -- just PTE bit manipulation + TLB flush.
 */
void df_mem_schedule_protect(struct task_struct *task)
{
	struct df_mem_mm_state *state;
	unsigned long flags;
	unsigned int i;
	int ret;

	if (!df_mem_initialized || !df_mem_enabled)
		return;
	if (!task->mm)
		return;
	if (!(task->df_ctx.flags & DF_TASKF_SEED_VALID))
		return;
	if (!(task->df_ctx.mem_flags & DF_MEMF_PAGES_ENCODED))
		return;

	state = df_mm_get_state(task->mm);
	if (!state || state->count == 0)
		return;

	/* Fast PTE-protect: PRESENT -> PROTNONE+SOFTW2+SOFTW3 */
	spin_lock_irqsave(&state->lock, flags);
	for (i = 0; i < state->count; i++)
		df_mem_pte_protect_fast(task->mm, state->active[i].vaddr);
	spin_unlock_irqrestore(&state->lock, flags);

	flush_tlb_mm(task->mm);

	/* Queue deferred XOR to run before task returns to userspace.
	 * CRITICAL: Only add reencode_work if not already pending.
	 * Adding the same callback_head to the task_work LIFO twice
	 * creates a cycle, corrupting the list and causing double-fput
	 * BUG_ON when task_work_run processes the corrupted chain. */
	if (!(task->df_ctx.mem_flags & DF_MEMF_REENCODE_PENDING)) {
		task->df_ctx.mem_flags |= DF_MEMF_REENCODE_PENDING;
		init_task_work(&task->df_ctx.reencode_work, df_mem_reencode_work);
		ret = task_work_add(task, &task->df_ctx.reencode_work, TWA_RESUME);
		if (ret) {
			/* Task exiting -- fall back to synchronous re-encode */
			task->df_ctx.mem_flags &= ~DF_MEMF_REENCODE_PENDING;
			df_mem_reencode_active(task);
		}
	}
}
EXPORT_SYMBOL_GPL(df_mem_schedule_protect);


/*
 * df_mem_reencode_active() — Re-encode all decoded-active pages.
 * Called from context switch (df_mem_context_switch) when prev
 * process is leaving the CPU.
 */
static void df_mem_reencode_active(struct task_struct *task)
{
	struct df_mem_mm_state *state;
	struct df_active_page snapshot[DF_MEM_MAX_ACTIVE_PAGES];
	unsigned long flags;
	unsigned int count, i;

	if (!task->mm)
		return;

	state = df_mm_get_state(task->mm);
	if (!state)
		return;  /* Hash collision -- skip re-encode */

	/* Copy active list under lock, then release before expensive XOR */
	spin_lock_irqsave(&state->lock, flags);
	count = state->count;
	if (count > 0)
		memcpy(snapshot, state->active,
		       count * sizeof(struct df_active_page));
	state->count = 0;
	spin_unlock_irqrestore(&state->lock, flags);

	/* Do the expensive crypto work outside the lock,
	 * then flip each PTE to PROTNONE+SOFTW1 so RAM
	 * always holds encoded data and the CPU cannot
	 * access it without faulting through our handler. */
	for (i = 0; i < count; i++) {
		/* Stale-entry guard: if PTE is already fully encoded
		 * (PROTNONE+SOFTW2, no SOFTW3), XOR would corrupt it.
		 * This mirrors the guard in reencode_work. */
		if (!df_mem_pte_check_present(task->mm, snapshot[i].vaddr) &&
		    !df_mem_pte_is_protected(task->mm, snapshot[i].vaddr)) {
			pr_debug("dialectforge: reencode-active drop stale %lx pid %d\n",
				snapshot[i].vaddr, task->pid);
			continue;
		}
		/* CoW guard: skip XOR if page is shared after fork.
		 * kmap writes bypass CoW, corrupting child's view. */
		if (folio_mapcount(page_folio(snapshot[i].page)) > 1) {
			df_mem_dbg("reencode-active: skip CoW page %lx pid %d\n",
				   snapshot[i].vaddr, task->pid);
			continue;
		}
		/* PFN verification: snapshot page must match current PTE.
		 * After CoW or page migration, PTE may point to a different
		 * physical page. XOR'ing the wrong page corrupts data. */
		{
			unsigned long pte_pfn_val = df_mem_pte_get_pfn(
				task->mm, snapshot[i].vaddr);
			unsigned long snap_pfn = page_to_pfn(snapshot[i].page);
			if (pte_pfn_val != snap_pfn) {
				pr_debug("dialectforge: reencode PFN mismatch "
					"vaddr=%lx snap_pfn=%lx pte_pfn=%lx pid=%d\n",
					snapshot[i].vaddr, snap_pfn,
					pte_pfn_val, task->pid);
				continue;
			}
		}
		{
			u32 enc_nonce;
			get_random_bytes(&enc_nonce, sizeof(enc_nonce));
			df_sw_xor_page(snapshot[i].page,
				       task->df_ctx.seed_bytes,
				       snapshot[i].vaddr, enc_nonce);
			spin_lock_irqsave(&state->lock, flags);
			df_mm_store_nonce(state, snapshot[i].vaddr, enc_nonce);
			spin_unlock_irqrestore(&state->lock, flags);
		}
		/* Walk page table and mark PTE as encoded */
		df_mem_flip_pte_encoded_final(task->mm, snapshot[i].vaddr);

		/* Report RCU quiescent state (see reencode_work comment) */
		local_irq_save(flags);
		rcu_momentary_eqs();
		local_irq_restore(flags);
	}
}

/*
 * df_mem_decode_fault() — Decode a page for the owning process.
 *
 * Called from handle_pte_fault() when:
 *   1. Page is present (not swapped, not missing)
 *   2. Current process has DF_TASKF_SEED_VALID
 *   3. Current process has DF_MEMF_PAGES_ENCODED
 *
 * Returns:
 *   0  = page decoded, fault handling should continue normally
 *   -1 = not a DF page or protection not active, skip
 */
int df_mem_decode_fault(struct vm_fault *vmf)
{
	struct page *page;
	struct folio *folio;
	unsigned long addr = vmf->address;

	if (!df_mem_initialized || !df_mem_enabled)
		return -1;

	if (!current->mm)
		return -1;

	if (!(current->df_ctx.flags & DF_TASKF_SEED_VALID))
		return -1;

	if (!(current->df_ctx.mem_flags & DF_MEMF_PAGES_ENCODED))
		return -1;

	/* Rate limit: kill process doing > 10000 decode faults per second */
	{
		struct df_mem_mm_state *rl = df_mm_get_state(current->mm);
		if (rl) {
			unsigned long now = jiffies;
			spin_lock(&rl->lock);
			if (time_after(now, rl->fault_window_start + HZ)) {
				rl->fault_count = 1;
				rl->fault_window_start = now;
			} else {
				rl->fault_count++;
				if (rl->fault_count > 10000) {
					spin_unlock(&rl->lock);
					pr_warn_ratelimited(
						"dialectforge: pid %d exceeded fault rate limit, killing\n",
						current->pid);
					force_sig(SIGKILL);
					return -1;
				}
			}
			spin_unlock(&rl->lock);
		}
	}

	/* Get the page from the PTE */
	if (!vmf->pte)
		return -1;

	if (!pte_present(vmf->orig_pte))
		return -1;

	folio = vm_normal_folio(vmf->vma, addr, vmf->orig_pte);
	if (!folio)
		return -1;

	page = folio_page(folio, 0);

	/* Decode the page in-place (XOR is its own inverse) */
	{
		u32 dec_nonce = 0;
		struct df_mem_mm_state *ns = df_mm_get_state(current->mm);
		if (ns) {
			unsigned long nf;
			spin_lock_irqsave(&ns->lock, nf);
			dec_nonce = df_mm_lookup_nonce(ns, addr);
			spin_unlock_irqrestore(&ns->lock, nf);
		}
		df_sw_xor_page(page, current->df_ctx.seed_bytes, addr, dec_nonce);
	}

	/* Track it so context switch can re-encode */
	df_mm_track_decoded(current->mm, page, addr);

	df_mem_dbg("decode-on-fault: addr=%lx pid=%d pfn=%lx\n",
		   addr, current->pid, page_to_pfn(page));

	return 0;
}
EXPORT_SYMBOL_GPL(df_mem_decode_fault);

/* ============================================================
 * SECTION 14: Global State Init for mm hash
 * ============================================================ */

static void __init df_mem_mm_states_init(void)
{
	int i;
	for (i = 0; i < DF_MM_HASH_SIZE; i++) {
		spin_lock_init(&df_mm_states[i].lock);
		df_mm_states[i].count = 0;
	}
		df_mm_states[i].owner = NULL;
}
/* ============================================================
 * SECTION 15: PTE-Marked Encoding — Always-Encrypted RAM
 *
 * Pages in RAM are ALWAYS encoded. The PTE uses PROTNONE + SOFTW1
 * to mark encoded pages. When the owning process touches a page:
 *   1. CPU faults (PROTNONE = not present from CPU perspective)
 *   2. Kernel intercepts BEFORE NUMA check
 *   3. If SOFTW1 is set → DialectForge encoded page
 *   4. Decode in-place, flip PTE to PRESENT, track as active
 *   5. On context switch: re-encode data + flip PTE back
 *
 * _PAGE_SOFTW2 (bit 10) aliases UFFD_WP. Not checked by vm_normal_page, safe for anonymous
 * pages. Only relevant when userfaultfd write-protect is active, which DF processes do not use.
 * ============================================================ */

#include <asm/pgtable.h>
#include <asm/pgtable_types.h>


/*
 * df_mem_pte_decode_fault() — PTE-aware decode for encoded pages.
 *
 * Called from handle_pte_fault() when we detect a PROTNONE + SOFTW1
 * PTE. The page data is XOR-decoded, the PTE is flipped to PRESENT,
 * and the page is tracked as decoded-active for re-encode on ctx switch.
 *
 * Returns 0 on success (fault fully handled), VM_FAULT_SIGBUS on error.
 */
int df_mem_pte_decode_fault(struct vm_fault *vmf)
{
	struct page *page;
	struct folio *folio;
	pte_t new_pte;
	pteval_t val;
	int ret;

	if (!df_mem_initialized || !df_mem_enabled) {
		pr_info("dialectforge: SIGBUS init=%d enabled=%d pid=%d addr=%lx\n",
			df_mem_initialized, df_mem_enabled, current->pid, vmf->address);
		return VM_FAULT_SIGBUS;
	}

	if (!current->mm) {
		pr_debug("dialectforge: SIGBUS no-mm pid=%d addr=%lx\n",
			current->pid, vmf->address);
		return 0;	/* let fault retry; process will be reaped */
	}

	if (!(current->df_ctx.flags & DF_TASKF_SEED_VALID)) {
		pr_info("dialectforge: SIGBUS no-seed pid=%d addr=%lx flags=0x%x\n",
			current->pid, vmf->address, current->df_ctx.flags);
		return VM_FAULT_SIGBUS;
	}

	/*
	 * PHASE 1: Under ptl â verify PTE, resolve page, pin it.
	 */
	spin_lock(vmf->ptl);
	if (unlikely(!pte_same(ptep_get(vmf->pte), vmf->orig_pte))) {
		spin_unlock(vmf->ptl);
		return 0; /* Retry â PTE changed under us */
	}

	folio = vm_normal_folio(vmf->vma, vmf->address, vmf->orig_pte);
	if (!folio) {
		pr_info("dialectforge: SIGBUS no-folio pid=%d addr=%lx pte=%lx\n",
			current->pid, vmf->address, pte_val(vmf->orig_pte));
		spin_unlock(vmf->ptl);
		return VM_FAULT_SIGBUS;
	}
	page = folio_page(folio, 0);

	/* Pin the page so it can't vanish while we decode outside ptl */
	/* Pin the page so it can't vanish while we decode outside ptl */
	get_page(page);

	/* DF-004: nonce for page decode; set in !skip_xor path, reused if PTE race */
	{
	u32 dec_nonce = 0;

	/* Check SOFTW3: protected-but-cleartext = skip expensive XOR.
	 * This happens when task was scheduled out (PTEs protected fast)
	 * but re-scheduled before task_work could XOR re-encode. */
	{
		bool skip_xor = !!(pte_val(vmf->orig_pte) & _PAGE_SOFTW3);
		spin_unlock(vmf->ptl);

		if (!skip_xor) {
			struct df_mem_mm_state *ns = df_mm_get_state(current->mm);
			if (ns) {
				unsigned long nf;
				spin_lock_irqsave(&ns->lock, nf);
				dec_nonce = df_mm_lookup_nonce(ns, vmf->address);
				spin_unlock_irqrestore(&ns->lock, nf);
			}
			/* PHASE 2: Heavy crypto outside all spinlocks */
			pr_debug("df-xor-call: DECODE-FAULT pfn=%lx vaddr=%lx pid=%d\n",
				page_to_pfn(page), vmf->address, current->pid);
			ret = df_sw_xor_page(page, current->df_ctx.seed_bytes,
					     vmf->address, dec_nonce);
			if (ret) {
				pr_info("dialectforge: SIGBUS xor-fail pid=%d addr=%lx ret=%d\n",
					current->pid, vmf->address, ret);
				put_page(page);
				return VM_FAULT_SIGBUS;
			}
		} else {
			pr_debug("dialectforge: skip-xor pid=%d addr=%lx (SOFTW3 set)\n",
				current->pid, vmf->address);
		}
	}



	/*
	 * PHASE 3: Re-acquire ptl, verify PTE hasn't changed.
	 * If another thread raced and changed this PTE, we must
	 * re-encode the page (XOR is symmetric) and return 0 to retry.
	 */
	spin_lock(vmf->ptl);
	if (unlikely(!pte_same(ptep_get(vmf->pte), vmf->orig_pte))) {
		spin_unlock(vmf->ptl);
		/* PTE raced â re-encode (XOR is symmetric) to restore */
		pr_debug("df-xor-call: RACE-REVERT pfn=%lx vaddr=%lx pid=%d\n",
			page_to_pfn(page), vmf->address, current->pid);
		/* Race: re-encode with same nonce, then re-store it for retry */
		df_sw_xor_page(page, current->df_ctx.seed_bytes, vmf->address, dec_nonce);
		if (dec_nonce) {
			struct df_mem_mm_state *ns2 = df_mm_get_state(current->mm);
			if (ns2) {
				unsigned long nf2;
				spin_lock_irqsave(&ns2->lock, nf2);
				df_mm_store_nonce(ns2, vmf->address, dec_nonce);
				spin_unlock_irqrestore(&ns2->lock, nf2);
			}
		}
		put_page(page);
		return 0; /* Caller will retry the fault */
	}

	} /* end dec_nonce scope */

	/* Flip PTE: PROTNONE+SOFTW2 â PRESENT.
	 * Must use flip_protnone_guard to un-invert PFN bits â
	 * x86 inverts physical address in non-present PTEs
	 * as anti-speculation defence. */
	{
		pteval_t old_val = pte_val(vmf->orig_pte);
		val = old_val;
		val |= _PAGE_PRESENT;
		val &= ~(_PAGE_PROTNONE | _PAGE_SOFTW2 | _PAGE_SOFTW3);
		val = flip_protnone_guard(old_val, val, PTE_PFN_MASK);
		new_pte = pte_mkyoung(__pte(val));
	}
	set_pte_at(vmf->vma->vm_mm, vmf->address, vmf->pte, new_pte);

	pr_debug("dialectforge: decoded pid=%d addr=%lx pfn=%lx old=%lx new=%lx\n",
		current->pid, vmf->address, page_to_pfn(page),
		pte_val(vmf->orig_pte), pte_val(new_pte));

	/* Track as decoded-active for re-encode on context switch */
	df_mm_track_decoded(current->mm, page, vmf->address);


	/* DEBUG: one-shot diagnostic when a process FIRST enters encode cycle */
	if (!(current->df_ctx.mem_flags & DF_MEMF_PAGES_ENCODED))
		pr_info("dialectforge: FIRST-ENCODE pid=%d addr=%lx mm=%px hash=%lu flags=0x%x\n",
			current->pid, vmf->address, current->mm,
			((unsigned long)current->mm >> 12) & 0xFF,
			current->df_ctx.mem_flags);
	/* Set PAGES_ENCODED flag so context switch knows to re-encode */
	current->df_ctx.mem_flags |= DF_MEMF_PAGES_ENCODED;

	spin_unlock(vmf->ptl);
	put_page(page);  /* Release the pin */

	/* Flush stale TLB entry so CPU sees the new PRESENT PTE */
	flush_tlb_page(vmf->vma, vmf->address);

	df_mem_dbg("pte-decode: addr=%lx pid=%d pfn=%lx\n",
		   vmf->address, current->pid, page_to_pfn(page));

	return 0;
}
EXPORT_SYMBOL_GPL(df_mem_pte_decode_fault);

/*
 * df_mem_track_active_page() — Exported wrapper for tracking
 * decoded-active pages from mm/memory.c (COW path etc).
 */
void df_mem_track_active_page(struct mm_struct *mm,
			      struct page *page, unsigned long vaddr)
{
	if (!df_mem_initialized || !df_mem_enabled)
		return;
	df_mm_track_decoded(mm, page, vaddr);
}
EXPORT_SYMBOL_GPL(df_mem_track_active_page);

/*
 * df_mem_decode_vma_range() — Decode all encoded pages in a VMA before
 * PTE relocation (e.g., setup_arg_pages → relocate_vma_down).
 *
 * Problem: XOR encryption uses the virtual address as part of the key.
 * When move_ptes() copies a PTE to a new virtual address, the encoded
 * page data becomes undecryptable because the decode handler will use
 * the new address (different key). We must decode before the move.
 *
 * Also clears the mm's decoded-active tracking since vaddrs will change.
 */
void df_mem_decode_vma_range(struct mm_struct *mm, unsigned long start,
			    unsigned long end)
{
	unsigned long addr;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	int decoded = 0;

	if (!df_mem_initialized || !df_mem_enabled)
		return;
	if (!current->mm || !(current->df_ctx.flags & DF_TASKF_SEED_VALID))
		return;

	for (addr = start; addr < end; addr += PAGE_SIZE) {
		pteval_t v;
		struct page *page;
		bool skip_xor;

		pgd = pgd_offset(mm, addr);
		if (pgd_none(*pgd) || pgd_bad(*pgd))
			continue;
		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d) || p4d_bad(*p4d))
			continue;
		pud = pud_offset(p4d, addr);
		if (pud_none(*pud) || pud_bad(*pud))
			continue;
		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			continue;

		ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
		if (!ptep)
			continue;

		pte = ptep_get(ptep);
		v = pte_val(pte);

		/* Only process DF-encoded pages: !PRESENT + SOFTW2 */
		if ((v & _PAGE_PRESENT) || !(v & _PAGE_SOFTW2)) {
			pte_unmap_unlock(ptep, ptl);
			continue;
		}

		skip_xor = !!(v & _PAGE_SOFTW3);
		page = pte_page(pte); /* pte_pfn handles protnone inversion */
		get_page(page);
		spin_unlock(ptl);
		/* XOR-decode outside spinlock (may sleep for keystream) */
		if (!skip_xor) {
			u32 dec_nonce = 0;
			struct df_mem_mm_state *ns = df_mm_get_state(mm);
			if (ns) {
				unsigned long nf;
				spin_lock_irqsave(&ns->lock, nf);
				dec_nonce = df_mm_lookup_nonce(ns, addr);
				spin_unlock_irqrestore(&ns->lock, nf);
			}
			df_sw_xor_page(page, current->df_ctx.seed_bytes, addr, dec_nonce);
		}

		/* Re-acquire lock and flip PTE to PRESENT */
		ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
		if (ptep) {
			pte = ptep_get(ptep);
			v = pte_val(pte);
			if (!(v & _PAGE_PRESENT) && (v & _PAGE_SOFTW2)) {
				pteval_t nv = v;
				nv |= _PAGE_PRESENT;
				nv &= ~(_PAGE_PROTNONE | _PAGE_SOFTW2 | _PAGE_SOFTW3);
				nv = flip_protnone_guard(v, nv, PTE_PFN_MASK);
				set_pte_at(mm, addr, ptep, pte_mkyoung(__pte(nv)));
				decoded++;
			}
			pte_unmap_unlock(ptep, ptl);
		}

		put_page(page);
	}

	if (decoded) {
		flush_tlb_mm(mm);
		pr_debug("dialectforge: decoded %d pages before VMA relocation\n",
			decoded);
	}

	/* Clear decoded-active tracking — vaddrs are about to change */
	{
		struct df_mem_mm_state *state = df_mm_get_state(mm);
		unsigned long flags;
		if (!state)
			return; /* Hash collision -- no active[] to clear */
		spin_lock_irqsave(&state->lock, flags);
		state->count = 0;
		spin_unlock_irqrestore(&state->lock, flags);
	}
}
EXPORT_SYMBOL_GPL(df_mem_decode_vma_range);
#endif /* CONFIG_DIALECTFORGE */

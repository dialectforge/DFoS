// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS — USB Auto-Quarantine Module
 *
 * When a USB block device appears, all content accessed from it is
 * automatically placed in a quarantine zone (Tier 2).  The boot
 * device is detected once at startup from the kernel command line
 * and is IMMUTABLE thereafter — it IS the atmosphere, not a visitor.
 *
 * Design constraints (from protocol spec):
 *   1. Boot device detected dynamically at startup from root= param
 *   2. Boot device identity is immutable once set — cannot be changed
 *   3. When USB device is disconnected, its quarantine zone is
 *      destroyed and seeds are crypto-wiped (TTL=0 immediate expire)
 *
 * Interface: /proc/df_usb_quarantine
 *   Read:  list tracked USB devices and boot device
 *   Write: "register <devname> <mount_path> [serial]"  — udev helper
 *          "unregister <devname>"                       — udev remove
 *
 * Copyright (C) 2026 John Dean Martin. OS: GPL. Protocol: Proprietary.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/namei.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/dialectforge.h>

/* ================================================================
 * Constants
 * ================================================================ */
#define DF_USB_MAX_DEVICES    16
#define DF_USB_MAX_DEVNAME    64
#define DF_USB_MAX_MOUNT      256
#define DF_USB_MAX_SERIAL     128
#define DF_USB_BOOT_LABEL     "boot-device"

/* ================================================================
 * Per-device tracking structure
 * ================================================================ */
struct df_usb_device {
	char              devname[DF_USB_MAX_DEVNAME];   /* e.g. "sda"       */
	char              mount_path[DF_USB_MAX_MOUNT];  /* e.g. "/mnt/usb0" */
	char              serial[DF_USB_MAX_SERIAL];     /* USB serial or "" */
	u32               zone_id;                        /* quarantine zone  */
	u64               registered_ns;                  /* ktime timestamp  */
	bool              active;                         /* currently mounted */
	struct list_head  list;
};

/* ================================================================
 * Module state
 * ================================================================ */
static DEFINE_SPINLOCK(df_usb_lock);
static LIST_HEAD(df_usb_devices);
static int df_usb_count = 0;

/* Boot device — set ONCE at init, immutable thereafter */
static char df_boot_device[DF_USB_MAX_DEVNAME] = "";
static char df_boot_disk[DF_USB_MAX_DEVNAME] = "";   /* disk-level: sda for sda1 */
static bool df_boot_device_locked = false;             /* true after first detection */

/* ================================================================
 * Boot device detection
 *
 * Parses saved_command_line for root=<dev> at module init.
 * Strips /dev/ prefix if present, and derives disk-level name
 * (e.g. "sda1" → "sda") so the entire physical disk is protected.
 *
 * This runs ONCE. df_boot_device_locked prevents any modification.
 * ================================================================ */
extern char *saved_command_line;   /* from init/main.c */

static void df_usb_strip_partition(const char *part, char *disk, size_t len)
{
	size_t plen;

	strscpy(disk, part, len);
	plen = strlen(disk);

	/* Strip trailing digits: sda1 → sda, nvme0n1p2 → nvme0n1p */
	while (plen > 0 && disk[plen - 1] >= '0' && disk[plen - 1] <= '9')
		disk[--plen] = '\0';

	/* For nvme: strip trailing 'p' too: nvme0n1p → nvme0n1 */
	if (plen > 0 && disk[plen - 1] == 'p') {
		/* Only if it looks like nvmeXnYpZ pattern */
		if (strstr(disk, "nvme"))
			disk[--plen] = '\0';
	}
}

static void __init df_usb_detect_boot_device(void)
{
	const char *p;
	const char *start;
	size_t len;

	if (!saved_command_line)
		return;

	p = strstr(saved_command_line, "root=");
	if (!p)
		return;

	p += 5;  /* skip "root=" */

	/* Skip /dev/ prefix if present */
	if (strncmp(p, "/dev/", 5) == 0)
		p += 5;

	/* Find end of device name (space or end of string) */
	start = p;
	while (*p && *p != ' ' && *p != '\t')
		p++;

	len = p - start;
	if (len == 0 || len >= DF_USB_MAX_DEVNAME)
		return;

	memcpy(df_boot_device, start, len);
	df_boot_device[len] = '\0';

	/*
	 * If root= used UUID=, PARTUUID=, or LABEL= format, the stored
	 * value is NOT a real device name yet.  We can't resolve it now
	 * because the real root filesystem isn't mounted yet (we run
	 * before switch_root).  Mark it as needing lazy resolution.
	 *
	 * df_usb_resolve_boot_device_lazy() will resolve it on the first
	 * call to df_usb_is_boot_device() — by which time udev is running
	 * and the real root is mounted.
	 */
	if (strncmp(df_boot_device, "UUID=", 5) == 0 ||
	    strncmp(df_boot_device, "PARTUUID=", 9) == 0 ||
	    strncmp(df_boot_device, "LABEL=", 6) == 0) {
		/* Store UUID string for now — will resolve lazily */
		df_boot_device_locked = true;
		pr_info("dialectforge/usb: boot device pending resolution: %s\n",
			df_boot_device);
		return;
	}

	/* Direct device name — resolve immediately */
	df_usb_strip_partition(df_boot_device, df_boot_disk,
			       sizeof(df_boot_disk));
	df_boot_device_locked = true;

	pr_info("dialectforge/usb: boot device detected: %s (disk: %s) [LOCKED]\n",
		df_boot_device, df_boot_disk);
}

/*
 * Lazy resolution of UUID/PARTUUID/LABEL boot device.
 *
 * Called on first use of df_usb_is_boot_device() — by then the
 * real root is mounted and we can look up the actual block device.
 * After resolution, df_boot_device contains the real name (e.g. sda3)
 * and all future comparisons work directly.
 */
static void df_usb_resolve_boot_device_lazy(void)
{
	struct path root_path;

	/* Already resolved? */
	if (df_boot_disk[0])
		return;

	/* Not a UUID/PARTUUID/LABEL — nothing to resolve */
	if (strncmp(df_boot_device, "UUID=", 5) != 0 &&
	    strncmp(df_boot_device, "PARTUUID=", 9) != 0 &&
	    strncmp(df_boot_device, "LABEL=", 6) != 0)
		return;

	if (kern_path("/", LOOKUP_FOLLOW, &root_path) == 0) {
		struct super_block *sb = root_path.mnt->mnt_sb;

		if (sb && sb->s_bdev) {
			struct block_device *bdev = sb->s_bdev;
			u8 partno = bdev_partno(bdev);

			if (partno > 0)
				snprintf(df_boot_device,
					 sizeof(df_boot_device),
					 "%s%u",
					 bdev->bd_disk->disk_name,
					 partno);
			else
				snprintf(df_boot_device,
					 sizeof(df_boot_device),
					 "%s",
					 bdev->bd_disk->disk_name);

			df_usb_strip_partition(df_boot_device, df_boot_disk,
					       sizeof(df_boot_disk));

			pr_info("dialectforge/usb: boot device resolved: "
				"%s (disk: %s) [LOCKED]\n",
				df_boot_device, df_boot_disk);
		}
		path_put(&root_path);
	}

	if (!df_boot_disk[0])
		pr_warn("dialectforge/usb: could not resolve boot device\n");
}

/* ================================================================
 * Boot device check (exported for LSM hooks)
 *
 * Returns true if devname belongs to the boot disk.
 * Matches at disk level: if boot is sda1, sda2 is also protected.
 * ================================================================ */
bool df_usb_is_boot_device(const char *devname)
{
	const char *name = devname;
	char disk[DF_USB_MAX_DEVNAME];

	if (!df_boot_device_locked || !devname)
		return false;

	/* Lazy resolve UUID/PARTUUID/LABEL on first use */
	df_usb_resolve_boot_device_lazy();

	/* Strip /dev/ prefix */
	if (strncmp(name, "/dev/", 5) == 0)
		name += 5;

	/* Exact match on partition */
	if (strcmp(name, df_boot_device) == 0)
		return true;

	/* Disk-level match: sda matches sda, sda1, sda2 etc */
	df_usb_strip_partition(name, disk, sizeof(disk));
	return strcmp(disk, df_boot_disk) == 0;
}
EXPORT_SYMBOL_GPL(df_usb_is_boot_device);

/* ================================================================
 * Quarantine path check (exported for LSM file_open hook)
 *
 * Returns true if the given path falls under any active USB
 * quarantine mount point.
 * ================================================================ */
bool df_usb_is_quarantine_path(const char *path)
{
	struct df_usb_device *dev;
	bool found = false;

	if (!path)
		return false;

	spin_lock(&df_usb_lock);
	list_for_each_entry(dev, &df_usb_devices, list) {
		if (!dev->active)
			continue;
		if (strncmp(path, dev->mount_path,
			    strlen(dev->mount_path)) == 0) {
			found = true;
			break;
		}
	}
	spin_unlock(&df_usb_lock);
	return found;
}
EXPORT_SYMBOL_GPL(df_usb_is_quarantine_path);

/* ================================================================
 * Device registration — called by udev helper
 *
 * Creates a quarantine zone for the USB device. Boot device
 * is silently skipped (it IS the atmosphere).
 * ================================================================ */
static int df_usb_register(const char *devname, const char *mount_path,
			   const char *serial)
{
	struct df_usb_device *dev;
	struct df_quarantine_zone *zone;

	/* Boot device is NEVER quarantined */
	if (df_usb_is_boot_device(devname)) {
		pr_debug("dialectforge/usb: %s is boot device — not quarantined\n",
			devname);
		return 0;
	}

	spin_lock(&df_usb_lock);

	/* Check for duplicates */
	list_for_each_entry(dev, &df_usb_devices, list) {
		if (strcmp(dev->devname, devname) == 0) {
			spin_unlock(&df_usb_lock);
			pr_warn("dialectforge/usb: %s already registered\n",
				devname);
			return -EEXIST;
		}
	}

	if (df_usb_count >= DF_USB_MAX_DEVICES) {
		spin_unlock(&df_usb_lock);
		pr_warn("dialectforge/usb: max devices reached (%d)\n",
			DF_USB_MAX_DEVICES);
		return -ENOSPC;
	}

	dev = kzalloc(sizeof(*dev), GFP_ATOMIC);
	if (!dev) {
		spin_unlock(&df_usb_lock);
		return -ENOMEM;
	}

	strscpy(dev->devname, devname, sizeof(dev->devname));
	strscpy(dev->mount_path, mount_path, sizeof(dev->mount_path));
	if (serial)
		strscpy(dev->serial, serial, sizeof(dev->serial));

	dev->registered_ns = ktime_get_ns();
	dev->active = true;

	list_add_tail(&dev->list, &df_usb_devices);
	df_usb_count++;

	spin_unlock(&df_usb_lock);

	/* Create quarantine zone for this device */
	zone = df_quarantine_zone_create(current->pid);
	if (zone) {
		dev->zone_id = zone->zone_id;
		pr_debug("dialectforge/usb: quarantined %s at %s (zone %u)\n",
			devname, mount_path, zone->zone_id);
	} else {
		dev->zone_id = 0;
		pr_warn("dialectforge/usb: %s registered but zone creation failed\n",
			devname);
	}

	return 0;
}

/* ================================================================
 * Device unregistration — called on USB disconnect
 *
 * Destroys the quarantine zone (crypto-wipes seeds) and frees
 * the tracking entry. This is the "disconnect closes it out"
 * requirement — there is no grace period, no TTL extension.
 * ================================================================ */
static int df_usb_unregister(const char *devname)
{
	struct df_usb_device *dev, *tmp;
	struct df_quarantine_zone *zone;
	bool found = false;

	spin_lock(&df_usb_lock);
	list_for_each_entry_safe(dev, tmp, &df_usb_devices, list) {
		if (strcmp(dev->devname, devname) == 0) {
			list_del(&dev->list);
			df_usb_count--;
			found = true;
			break;
		}
	}
	spin_unlock(&df_usb_lock);

	if (!found) {
		pr_warn("dialectforge/usb: unregister %s — not found\n",
			devname);
		return -ENOENT;
	}

	/* Destroy quarantine zone — immediate crypto-wipe */
	if (dev->zone_id) {
		zone = df_quarantine_zone_find(dev->zone_id);
		if (zone) {
			pr_info("dialectforge/usb: destroying zone %u for %s\n",
				dev->zone_id, devname);
			df_quarantine_zone_destroy(zone);
		}
	}

	pr_info("dialectforge/usb: %s unregistered and wiped\n", devname);
	kfree(dev);
	return 0;
}

/* ================================================================
 * /proc/df_usb_quarantine — read interface
 * ================================================================ */
static int df_usb_proc_show(struct seq_file *m, void *v)
{
	struct df_usb_device *dev;

	seq_printf(m, "boot_device: %s (disk: %s) [%s]\n",
		   df_boot_device[0] ? df_boot_device : "(none)",
		   df_boot_disk[0] ? df_boot_disk : "(none)",
		   df_boot_device_locked ? "LOCKED" : "unset");
	seq_printf(m, "tracked_devices: %d/%d\n",
		   df_usb_count, DF_USB_MAX_DEVICES);
	seq_putc(m, '\n');

	spin_lock(&df_usb_lock);
	list_for_each_entry(dev, &df_usb_devices, list) {
		seq_printf(m, "[%s] %s -> %s  zone=%u serial=%s\n",
			   dev->active ? "ACTIVE" : "GONE",
			   dev->devname, dev->mount_path,
			   dev->zone_id,
			   dev->serial[0] ? dev->serial : "(none)");
	}
	spin_unlock(&df_usb_lock);

	return 0;
}

/* ================================================================
 * /proc/df_usb_quarantine — write interface
 *
 * Commands:
 *   register <devname> <mount_path> [serial]
 *   unregister <devname>
 * ================================================================ */
static ssize_t df_usb_proc_write(struct file *file,
				 const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char kbuf[512];
	char *p, *cmd, *devname, *mount_path, *serial;
	int ret;

	/* DFoS: Require CAP_SYS_ADMIN for USB quarantine control */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	/* Strip trailing newline */
	p = strchr(kbuf, '\n');
	if (p)
		*p = '\0';

	/* Parse command */
	p = kbuf;
	cmd = strsep(&p, " ");
	if (!cmd)
		return -EINVAL;

	if (strcmp(cmd, "register") == 0) {
		if (!p)
			return -EINVAL;
		devname = strsep(&p, " ");
		mount_path = strsep(&p, " ");
		serial = p;  /* optional, may be NULL */

		if (!devname || !mount_path)
			return -EINVAL;

		ret = df_usb_register(devname, mount_path, serial);
		return ret ? ret : count;

	} else if (strcmp(cmd, "unregister") == 0) {
		if (!p)
			return -EINVAL;
		devname = strsep(&p, " ");
		if (!devname)
			return -EINVAL;

		ret = df_usb_unregister(devname);
		return ret ? ret : count;
	}

	return -EINVAL;
}

static int df_usb_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, df_usb_proc_show, NULL);
}

static const struct proc_ops df_usb_proc_ops = {
	.proc_open    = df_usb_proc_open,
	.proc_read    = seq_read,
	.proc_write   = df_usb_proc_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ================================================================
 * Init / Cleanup
 * ================================================================ */
int __init df_usb_quarantine_init(void)
{
	struct proc_dir_entry *entry;

	/* Detect boot device from kernel command line — ONCE */
	df_usb_detect_boot_device();

	entry = proc_create("df_usb_quarantine", 0640, NULL,
			    &df_usb_proc_ops);
	if (!entry) {
		pr_err("dialectforge/usb: failed to create /proc/df_usb_quarantine\n");
		return -ENOMEM;
	}

	pr_info("dialectforge/usb: USB auto-quarantine initialized\n");
	return 0;
}

void df_usb_quarantine_cleanup(void)
{
	struct df_usb_device *dev, *tmp;
	struct df_quarantine_zone *zone;

	remove_proc_entry("df_usb_quarantine", NULL);

	/* Destroy all quarantine zones on shutdown */
	spin_lock(&df_usb_lock);
	list_for_each_entry_safe(dev, tmp, &df_usb_devices, list) {
		if (dev->zone_id) {
			zone = df_quarantine_zone_find(dev->zone_id);
			if (zone)
				df_quarantine_zone_destroy(zone);
		}
		list_del(&dev->list);
		kfree(dev);
	}
	df_usb_count = 0;
	spin_unlock(&df_usb_lock);

	pr_info("dialectforge/usb: cleanup complete\n");
}

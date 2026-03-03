/*
 * dfctl — DialectForge OS control utility
 *
 * Userspace CLI for managing process tiers, quarantine zones,
 * memory protection, and system diagnostics.
 *
 * Usage:
 *   dfctl status          Show all process tiers
 *   dfctl promote <pid>   Promote process from quarantine to adopted
 *   dfctl quarantine <pid> Force process into quarantine zone
 *   dfctl mem              Show memory protection status
 *   dfctl info             Show DialectForge system info
 *   dfctl version          Show version
 *
 * Copyright (C) 2026 John Dean Martin. All Rights Reserved.
 * Patent Pending.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define DFCTL_PROC      "/proc/dfctl"
#define DF_INFO_PROC    "/proc/dialectforge"
#define DF_MEM_PROC     "/proc/df_mem_enable"
#define DF_SYSCTL_BASE  "/proc/sys/dialectforge"

#define VERSION         "1.0.0"
#define BANNER \
    "dfctl v" VERSION " — DialectForge OS Control\n" \
    "Copyright (c) 2026 John Dean Martin. Patent Pending.\n"

static int read_file(const char *path, char *buf, size_t bufsz)
{
    int fd = open(path, O_RDONLY);
    ssize_t n;
    if (fd < 0)
        return -errno;
    n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n < 0)
        return -errno;
    buf[n] = '\0';
    return 0;
}

static int write_file(const char *path, const char *data, size_t len)
{
    int fd = open(path, O_WRONLY);
    ssize_t n;
    if (fd < 0)
        return -errno;
    n = write(fd, data, len);
    close(fd);
    if (n < 0)
        return -errno;
    return 0;
}

/* dfctl status — read /proc/dfctl */
static int cmd_status(void)
{
    char buf[8192];
    int ret = read_file(DFCTL_PROC, buf, sizeof(buf));
    if (ret) {
        fprintf(stderr, "dfctl: cannot read %s: %s\n",
                DFCTL_PROC, strerror(-ret));
        return 1;
    }
    printf("%s", buf);
    return 0;
}

/* dfctl promote <pid> */
static int cmd_promote(const char *pid_str)
{
    char cmd[64];
    int ret;

    snprintf(cmd, sizeof(cmd), "promote %s", pid_str);
    ret = write_file(DFCTL_PROC, cmd, strlen(cmd));
    if (ret) {
        fprintf(stderr, "dfctl: promote failed: %s\n", strerror(-ret));
        return 1;
    }
    printf("Process %s promoted to adopted tier\n", pid_str);
    return 0;
}

/* dfctl quarantine <pid> */
static int cmd_quarantine(const char *pid_str)
{
    char cmd[64];
    int ret;

    snprintf(cmd, sizeof(cmd), "quarantine %s", pid_str);
    ret = write_file(DFCTL_PROC, cmd, strlen(cmd));
    if (ret) {
        fprintf(stderr, "dfctl: quarantine failed: %s\n", strerror(-ret));
        return 1;
    }
    printf("Process %s forced to quarantine\n", pid_str);
    return 0;
}

/* dfctl mem — memory protection status */
static int cmd_mem(void)
{
    char buf[32];
    int ret;

    printf("=== Memory Protection ===\n");
    ret = read_file(DF_MEM_PROC, buf, sizeof(buf));
    if (ret) {
        printf("  Status: unavailable (%s)\n", strerror(-ret));
        return 1;
    }
    /* Trim newline */
    buf[strcspn(buf, "\n")] = '\0';
    printf("  Enabled: %s\n", buf[0] == '1' ? "YES" : "NO");
    return 0;
}

/* dfctl info — system overview */
static int cmd_info(void)
{
    char buf[4096];
    char sysctl[128];
    int ret;
    const char *sysctls[] = {
        "cycle_interval_ms", "cycle_jitter_ms", "cipher_mode",
        "debug_level", "anomaly_threshold", "quarantine_ttl_ms",
        NULL
    };
    int i;

    printf("=== DialectForge System Info ===\n\n");

    /* Main proc entry */
    ret = read_file(DF_INFO_PROC, buf, sizeof(buf));
    if (ret == 0)
        printf("%s\n", buf);
    else
        printf("  (no /proc/dialectforge)\n\n");

    /* Memory protection */
    cmd_mem();
    printf("\n");

    /* Sysctl values */
    printf("=== Sysctl Parameters ===\n");
    for (i = 0; sysctls[i]; i++) {
        char path[256];
        snprintf(path, sizeof(path), "%s/%s", DF_SYSCTL_BASE, sysctls[i]);
        ret = read_file(path, sysctl, sizeof(sysctl));
        if (ret == 0) {
            sysctl[strcspn(sysctl, "\n")] = '\0';
            printf("  %-24s = %s\n", sysctls[i], sysctl);
        }
    }

    return 0;
}

static void usage(void)
{
    printf(BANNER);
    printf("\nUsage: dfctl <command> [args]\n\n");
    printf("Commands:\n");
    printf("  status              Show all process tiers\n");
    printf("  promote <pid>       Promote process to adopted tier\n");
    printf("  quarantine <pid>    Force process into quarantine\n");
    printf("  mem                 Show memory protection status\n");
    printf("  info                Full system diagnostics\n");
    printf("  version             Show version\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "status") == 0)
        return cmd_status();

    if (strcmp(argv[1], "promote") == 0) {
        if (argc < 3) {
            fprintf(stderr, "dfctl: promote requires a PID\n");
            return 1;
        }
        return cmd_promote(argv[2]);
    }

    if (strcmp(argv[1], "quarantine") == 0) {
        if (argc < 3) {
            fprintf(stderr, "dfctl: quarantine requires a PID\n");
            return 1;
        }
        return cmd_quarantine(argv[2]);
    }

    if (strcmp(argv[1], "mem") == 0)
        return cmd_mem();

    if (strcmp(argv[1], "info") == 0)
        return cmd_info();

    if (strcmp(argv[1], "version") == 0) {
        printf(BANNER);
        return 0;
    }

    if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }

    fprintf(stderr, "dfctl: unknown command '%s'\n", argv[1]);
    usage();
    return 1;
}

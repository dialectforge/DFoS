/*
 * dfpkg — DialectForge OS Package Manager
 *
 * Handles the adoption pipeline for software on DialectForge OS:
 *   Fetch → Verify → Relink → Assign Seed → Install → Audit
 *
 * Packages arrive through the Mod Translator in quarantine tier.
 * dfpkg verifies signatures, relinks against DF system libs,
 * assigns scoped seed contexts, and installs as adopted-tier software.
 *
 * Usage:
 *   dfpkg install <url|path>    Fetch, verify, relink, seed, install
 *   dfpkg remove <package>      Revoke seed, uninstall package
 *   dfpkg list                  List all adopted packages
 *   dfpkg audit                 Audit installed packages
 *   dfpkg verify <package>      Re-verify package signature
 *   dfpkg info <package>        Show package details and seed scope
 *   dfpkg update                Update package index
 *   dfpkg upgrade [package]     Upgrade package(s) to latest version
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define DFPKG_DB        "/var/lib/dfpkg"
#define DFPKG_CACHE     "/var/cache/dfpkg"
#define DFPKG_QUARANTINE "/var/lib/dfpkg/quarantine"
#define DFPKG_ADOPTED   "/var/lib/dfpkg/adopted"
#define DFPKG_KEYRING   "/etc/dfpkg/trusted.d"
#define DFPKG_INDEX     "/var/lib/dfpkg/index"
#define DFCTL_PROC      "/proc/dfctl"
#define DF_INFO_PROC    "/proc/dialectforge"
#define DF_PREFIX       "/opt/df"

#define DFPKG_VERSION   "1.0.0"
#define MAX_PKG_NAME    128
#define MAX_PATH_LEN    512
#define SHA256_HEX_LEN  65

/* ── Package metadata ─────────────────────────────────── */

struct dfpkg_meta {
	char name[MAX_PKG_NAME];
	char version[32];
	char sha256[SHA256_HEX_LEN];
	char seed_scope[64];       /* seed permission scope */
	int  tier;                  /* 0=quarantine, 1=adopted, 2=native */
	time_t installed;
	time_t verified;
	char origin[MAX_PATH_LEN]; /* original URL or path */
};

/* ── Helpers ──────────────────────────────────────────── */

static int run_cmd(const char *cmd)
{
	int rc = system(cmd);
	if (rc == -1) {
		perror("system");
		return -1;
	}
	return WEXITSTATUS(rc);
}

static int dir_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int file_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int ensure_dir(const char *path)
{
	if (dir_exists(path))
		return 0;
	char cmd[MAX_PATH_LEN + 16];
	snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", path);
	return run_cmd(cmd);
}

static int sha256_file(const char *path, char *out)
{
	FILE *f = fopen(path, "rb");
	if (!f) return -1;

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) { fclose(f); return -1; }

	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

	unsigned char buf[8192];
	size_t n;
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		EVP_DigestUpdate(ctx, buf, n);
	fclose(f);

	unsigned char hash[32];
	unsigned int len;
	EVP_DigestFinal_ex(ctx, hash, &len);
	EVP_MD_CTX_free(ctx);

	for (unsigned int i = 0; i < len; i++)
		sprintf(out + i * 2, "%02x", hash[i]);
	out[64] = '\0';
	return 0;
}

/* ── Pipeline Stage 1: Fetch ─────────────────────────── */

static int stage_fetch(const char *source, char *local_path, size_t len)
{
	ensure_dir(DFPKG_CACHE);
	ensure_dir(DFPKG_QUARANTINE);

	/* Determine filename from source */
	const char *basename = strrchr(source, '/');
	basename = basename ? basename + 1 : source;

	snprintf(local_path, len, "%s/%s", DFPKG_QUARANTINE, basename);

	if (strncmp(source, "http://", 7) == 0 ||
	    strncmp(source, "https://", 8) == 0) {
		/* Network fetch — arrives through Mod Translator */
		printf("  [fetch] Downloading %s ...\n", source);
		char cmd[MAX_PATH_LEN * 2 + 64];
		snprintf(cmd, sizeof(cmd),
			 "wget -q -O '%s' '%s' 2>&1", local_path, source);
		if (run_cmd(cmd) != 0) {
			/* Fallback to curl */
			snprintf(cmd, sizeof(cmd),
				 "curl -sfL -o '%s' '%s' 2>&1",
				 local_path, source);
			if (run_cmd(cmd) != 0) {
				fprintf(stderr, "dfpkg: fetch failed: %s\n", source);
				return -1;
			}
		}
	} else if (file_exists(source)) {
		/* Local file — copy into quarantine */
		printf("  [fetch] Copying %s into quarantine ...\n", source);
		char cmd[MAX_PATH_LEN * 2 + 32];
		snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", source, local_path);
		if (run_cmd(cmd) != 0) {
			fprintf(stderr, "dfpkg: copy failed\n");
			return -1;
		}
	} else {
		fprintf(stderr, "dfpkg: source not found: %s\n", source);
		return -1;
	}

	printf("  [fetch] OK → quarantine: %s\n", local_path);
	return 0;
}

/* ── Pipeline Stage 2: Verify ────────────────────────── */

static int stage_verify(const char *pkg_path, struct dfpkg_meta *meta)
{
	printf("  [verify] Computing SHA-256 ...\n");
	if (sha256_file(pkg_path, meta->sha256) != 0) {
		fprintf(stderr, "dfpkg: hash computation failed\n");
		return -1;
	}
	printf("  [verify] SHA-256: %s\n", meta->sha256);

	/* Check signature against trusted keyring */
	char sig_path[MAX_PATH_LEN + 8];
	snprintf(sig_path, sizeof(sig_path), "%s.sig", pkg_path);

	if (file_exists(sig_path)) {
		printf("  [verify] Checking signature ...\n");
		/* Verify detached GPG/PGP signature */
		char cmd[MAX_PATH_LEN * 2 + 128];
		snprintf(cmd, sizeof(cmd),
			 "gpg --homedir '%s' --verify '%s' '%s' 2>&1",
			 DFPKG_KEYRING, sig_path, pkg_path);
		if (run_cmd(cmd) != 0) {
			fprintf(stderr, "dfpkg: SIGNATURE VERIFICATION FAILED\n");
			fprintf(stderr, "dfpkg: package is UNTRUSTED — aborting\n");
			return -1;
		}
		printf("  [verify] Signature: VALID\n");
	} else {
		printf("  [verify] WARNING: No signature file — package unverified\n");
		printf("  [verify] Install will proceed in QUARANTINE-ONLY mode\n");
		meta->tier = 0; /* stays quarantine until signed */
	}

	return 0;
}

/* ── Pipeline Stage 3: Relink ────────────────────────── */

static int stage_relink(const char *pkg_path, const char *pkg_name)
{
	printf("  [relink] Checking binary compatibility ...\n");

	/* Check if it's an ELF binary that needs relinking */
	char cmd[MAX_PATH_LEN + 64];
	snprintf(cmd, sizeof(cmd), "file '%s' 2>/dev/null | grep -q ELF", pkg_path);

	if (run_cmd(cmd) != 0) {
		printf("  [relink] Not an ELF binary — skip relink\n");
		return 0;
	}

	/* Check dynamic dependencies */
	snprintf(cmd, sizeof(cmd), "ldd '%s' 2>/dev/null", pkg_path);
	printf("  [relink] Checking dynamic dependencies:\n");
	run_cmd(cmd);

	/* Relink against DF system libraries if available */
	char df_lib[MAX_PATH_LEN];
	snprintf(df_lib, sizeof(df_lib), "%s/lib", DF_PREFIX);

	if (dir_exists(df_lib)) {
		printf("  [relink] Patching RPATH to include %s ...\n", df_lib);
		snprintf(cmd, sizeof(cmd),
			 "patchelf --set-rpath '%s:/usr/lib:/lib' '%s' 2>&1",
			 df_lib, pkg_path);
		if (run_cmd(cmd) != 0)
			printf("  [relink] patchelf not available — skip RPATH\n");
		else
			printf("  [relink] RPATH updated\n");
	}

	printf("  [relink] OK\n");
	return 0;
}

/* ── Pipeline Stage 4: Assign Seed ───────────────────── */

static int stage_assign_seed(const char *pkg_name, struct dfpkg_meta *meta)
{
	printf("  [seed] Assigning scoped seed context ...\n");

	/* Generate seed scope from package name */
	snprintf(meta->seed_scope, sizeof(meta->seed_scope),
		 "pkg:%s:v%s", pkg_name, meta->version);

	/* Write seed assignment to dfctl proc interface */
	int fd = open(DFCTL_PROC, O_WRONLY);
	if (fd >= 0) {
		char cmd_buf[256];
		int n = snprintf(cmd_buf, sizeof(cmd_buf),
				 "seed-assign %s %s",
				 pkg_name, meta->seed_scope);
		if (write(fd, cmd_buf, n) < 0)
			perror("dfpkg: seed assign write");
		close(fd);
		printf("  [seed] Scope: %s\n", meta->seed_scope);
	} else {
		/* Running outside DF kernel — record for later */
		printf("  [seed] Kernel not available — recording scope: %s\n",
		       meta->seed_scope);
	}

	if (meta->tier != 0) /* 0 = quarantine-only (unsigned) */
		meta->tier = 1;  /* adopted */

	printf("  [seed] Tier: %s\n",
	       meta->tier == 0 ? "QUARANTINE" :
	       meta->tier == 1 ? "ADOPTED" : "NATIVE");
	return 0;
}

/* ── Pipeline Stage 5: Install ───────────────────────── */

static int stage_install(const char *pkg_path, struct dfpkg_meta *meta)
{
	char install_dir[MAX_PATH_LEN];

	if (meta->tier == 0)
		snprintf(install_dir, sizeof(install_dir),
			 "%s/%s", DFPKG_QUARANTINE, meta->name);
	else
		snprintf(install_dir, sizeof(install_dir),
			 "%s/bin", DF_PREFIX);

	ensure_dir(install_dir);

	char dest[MAX_PATH_LEN];
	snprintf(dest, sizeof(dest), "%s/%s", install_dir, meta->name);

	printf("  [install] Installing to %s ...\n", dest);
	char cmd[MAX_PATH_LEN * 2 + 32];
	snprintf(cmd, sizeof(cmd), "cp '%s' '%s' && chmod 755 '%s'",
		 pkg_path, dest, dest);

	if (run_cmd(cmd) != 0) {
		fprintf(stderr, "dfpkg: install failed\n");
		return -1;
	}

	meta->installed = time(NULL);
	printf("  [install] OK\n");
	return 0;
}

/* ── Pipeline Stage 6: Audit Record ──────────────────── */

static int stage_audit(struct dfpkg_meta *meta)
{
	ensure_dir(DFPKG_ADOPTED);

	char audit_path[MAX_PATH_LEN];
	snprintf(audit_path, sizeof(audit_path),
		 "%s/%s.meta", DFPKG_ADOPTED, meta->name);

	FILE *f = fopen(audit_path, "w");
	if (!f) {
		perror("dfpkg: audit record");
		return -1;
	}

	fprintf(f, "name=%s\n", meta->name);
	fprintf(f, "version=%s\n", meta->version);
	fprintf(f, "sha256=%s\n", meta->sha256);
	fprintf(f, "seed_scope=%s\n", meta->seed_scope);
	fprintf(f, "tier=%d\n", meta->tier);
	fprintf(f, "installed=%ld\n", (long)meta->installed);
	fprintf(f, "origin=%s\n", meta->origin);
	fclose(f);

	printf("  [audit] Recorded in %s\n", audit_path);
	return 0;
}

/* ── Commands ─────────────────────────────────────────── */

static int cmd_install(const char *source)
{
	struct dfpkg_meta meta = {0};
	char local_path[MAX_PATH_LEN];

	/* Extract package name from source */
	const char *bn = strrchr(source, '/');
	bn = bn ? bn + 1 : source;
	snprintf(meta.name, sizeof(meta.name), "%s", bn);
	/* Strip common extensions */
	char *dot = strstr(meta.name, ".tar");
	if (!dot) dot = strstr(meta.name, ".pkg");
	if (!dot) dot = strrchr(meta.name, '.');
	if (dot) *dot = '\0';

	snprintf(meta.version, sizeof(meta.version), "1.0.0");
	snprintf(meta.origin, sizeof(meta.origin), "%s", source);
	meta.tier = 1; /* default: adopted (downgraded to 0 if unsigned) */

	printf("dfpkg: installing %s\n", meta.name);
	printf("────────────────────────────────\n");

	if (stage_fetch(source, local_path, sizeof(local_path)) != 0)
		return 1;
	if (stage_verify(local_path, &meta) != 0)
		return 1;
	if (stage_relink(local_path, meta.name) != 0)
		return 1;
	if (stage_assign_seed(meta.name, &meta) != 0)
		return 1;
	if (stage_install(local_path, &meta) != 0)
		return 1;
	if (stage_audit(&meta) != 0)
		return 1;

	printf("────────────────────────────────\n");
	printf("dfpkg: %s installed successfully (%s)\n",
	       meta.name,
	       meta.tier == 0 ? "QUARANTINE" : "ADOPTED");
	return 0;
}

static int cmd_remove(const char *pkg_name)
{
	char meta_path[MAX_PATH_LEN];
	snprintf(meta_path, sizeof(meta_path),
		 "%s/%s.meta", DFPKG_ADOPTED, pkg_name);

	if (!file_exists(meta_path)) {
		fprintf(stderr, "dfpkg: package not found: %s\n", pkg_name);
		return 1;
	}

	printf("dfpkg: removing %s\n", pkg_name);

	/* Revoke seed through dfctl */
	int fd = open(DFCTL_PROC, O_WRONLY);
	if (fd >= 0) {
		char cmd_buf[256];
		int n = snprintf(cmd_buf, sizeof(cmd_buf),
				 "seed-revoke pkg:%s", pkg_name);
		write(fd, cmd_buf, n);
		close(fd);
		printf("  [seed] Revoked\n");
	}

	/* Remove binary */
	char bin_path[MAX_PATH_LEN];
	snprintf(bin_path, sizeof(bin_path), "%s/bin/%s", DF_PREFIX, pkg_name);
	unlink(bin_path);

	/* Remove quarantine copy */
	char qpath[MAX_PATH_LEN];
	snprintf(qpath, sizeof(qpath), "%s/%s", DFPKG_QUARANTINE, pkg_name);
	unlink(qpath);

	/* Remove audit record */
	unlink(meta_path);

	printf("dfpkg: %s removed\n", pkg_name);
	return 0;
}

static int cmd_list(void)
{
	DIR *d = opendir(DFPKG_ADOPTED);
	if (!d) {
		printf("dfpkg: no packages installed\n");
		return 0;
	}

	printf("%-24s %-12s %-12s %-10s\n",
	       "PACKAGE", "VERSION", "TIER", "SEED SCOPE");
	printf("────────────────────────────────────────────────────────────\n");

	struct dirent *ent;
	while ((ent = readdir(d)) != NULL) {
		if (!strstr(ent->d_name, ".meta"))
			continue;

		char path[MAX_PATH_LEN];
		snprintf(path, sizeof(path), "%s/%s", DFPKG_ADOPTED, ent->d_name);

		FILE *f = fopen(path, "r");
		if (!f) continue;

		char name[MAX_PKG_NAME] = "", ver[32] = "", scope[64] = "";
		int tier = -1;
		char line[256];

		while (fgets(line, sizeof(line), f)) {
			line[strcspn(line, "\n")] = '\0';
			if (strncmp(line, "name=", 5) == 0)
				snprintf(name, sizeof(name), "%s", line + 5);
			else if (strncmp(line, "version=", 8) == 0)
				snprintf(ver, sizeof(ver), "%s", line + 8);
			else if (strncmp(line, "seed_scope=", 11) == 0)
				snprintf(scope, sizeof(scope), "%s", line + 11);
			else if (strncmp(line, "tier=", 5) == 0)
				tier = atoi(line + 5);
		}
		fclose(f);

		const char *tier_str = tier == 0 ? "QUARANTINE" :
		                       tier == 1 ? "ADOPTED" :
		                       tier == 2 ? "NATIVE" : "UNKNOWN";

		printf("%-24s %-12s %-12s %-10s\n", name, ver, tier_str, scope);
	}
	closedir(d);
	return 0;
}

static int cmd_audit(void)
{
	printf("dfpkg audit — verifying all installed packages\n");
	printf("────────────────────────────────────────────────\n");

	DIR *d = opendir(DFPKG_ADOPTED);
	if (!d) {
		printf("No packages installed.\n");
		return 0;
	}

	int total = 0, ok = 0, fail = 0;
	struct dirent *ent;

	while ((ent = readdir(d)) != NULL) {
		if (!strstr(ent->d_name, ".meta"))
			continue;

		char path[MAX_PATH_LEN];
		snprintf(path, sizeof(path), "%s/%s", DFPKG_ADOPTED, ent->d_name);

		FILE *f = fopen(path, "r");
		if (!f) continue;

		char name[MAX_PKG_NAME] = "", expected_hash[SHA256_HEX_LEN] = "";
		int tier = -1;
		char line[256];

		while (fgets(line, sizeof(line), f)) {
			line[strcspn(line, "\n")] = '\0';
			if (strncmp(line, "name=", 5) == 0)
				snprintf(name, sizeof(name), "%s", line + 5);
			else if (strncmp(line, "sha256=", 7) == 0)
				snprintf(expected_hash, sizeof(expected_hash),
					 "%s", line + 7);
			else if (strncmp(line, "tier=", 5) == 0)
				tier = atoi(line + 5);
		}
		fclose(f);

		/* Find installed binary */
		char bin_path[MAX_PATH_LEN];
		if (tier == 0)
			snprintf(bin_path, sizeof(bin_path),
				 "%s/%s", DFPKG_QUARANTINE, name);
		else
			snprintf(bin_path, sizeof(bin_path),
				 "%s/bin/%s", DF_PREFIX, name);

		total++;
		if (!file_exists(bin_path)) {
			printf("  MISSING: %s (%s)\n", name, bin_path);
			fail++;
			continue;
		}

		char actual_hash[SHA256_HEX_LEN];
		if (sha256_file(bin_path, actual_hash) != 0) {
			printf("  ERROR: %s — cannot hash\n", name);
			fail++;
			continue;
		}

		if (strcmp(expected_hash, actual_hash) != 0) {
			printf("  TAMPERED: %s\n", name);
			printf("    expected: %s\n", expected_hash);
			printf("    actual:   %s\n", actual_hash);
			fail++;
		} else {
			printf("  OK: %s\n", name);
			ok++;
		}
	}
	closedir(d);

	printf("────────────────────────────────────────────────\n");
	printf("Audited: %d  OK: %d  Failed: %d\n", total, ok, fail);
	return fail > 0 ? 1 : 0;
}

static int cmd_info(const char *pkg_name)
{
	char meta_path[MAX_PATH_LEN];
	snprintf(meta_path, sizeof(meta_path),
		 "%s/%s.meta", DFPKG_ADOPTED, pkg_name);

	if (!file_exists(meta_path)) {
		fprintf(stderr, "dfpkg: package not found: %s\n", pkg_name);
		return 1;
	}

	FILE *f = fopen(meta_path, "r");
	if (!f) { perror("fopen"); return 1; }

	char line[256];
	printf("Package: %s\n", pkg_name);
	while (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\n")] = '\0';
		char *eq = strchr(line, '=');
		if (eq) {
			*eq = '\0';
			printf("  %-14s %s\n", line, eq + 1);
		}
	}
	fclose(f);
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"dfpkg %s — DialectForge Package Manager\n"
		"\n"
		"Usage:\n"
		"  dfpkg install <url|path>  Fetch, verify, relink, seed, install\n"
		"  dfpkg remove <package>    Revoke seed and uninstall\n"
		"  dfpkg list                List installed packages\n"
		"  dfpkg audit               Verify integrity of all packages\n"
		"  dfpkg info <package>      Show package details\n"
		"  dfpkg version             Show version\n"
		"\n"
		"Adoption Pipeline:\n"
		"  Fetch → Verify → Relink → Assign Seed → Install → Audit\n"
		"\n"
		"All packages enter quarantine. Signed packages are promoted\n"
		"to adopted tier with scoped seed contexts.\n",
		DFPKG_VERSION);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 1;
	}

	if (strcmp(argv[1], "install") == 0) {
		if (argc < 3) {
			fprintf(stderr, "dfpkg: install requires a source\n");
			return 1;
		}
		return cmd_install(argv[2]);
	}
	if (strcmp(argv[1], "remove") == 0) {
		if (argc < 3) {
			fprintf(stderr, "dfpkg: remove requires a package name\n");
			return 1;
		}
		return cmd_remove(argv[2]);
	}
	if (strcmp(argv[1], "list") == 0)
		return cmd_list();
	if (strcmp(argv[1], "audit") == 0)
		return cmd_audit();
	if (strcmp(argv[1], "info") == 0) {
		if (argc < 3) {
			fprintf(stderr, "dfpkg: info requires a package name\n");
			return 1;
		}
		return cmd_info(argv[2]);
	}
	if (strcmp(argv[1], "version") == 0) {
		printf("dfpkg %s\n", DFPKG_VERSION);
		return 0;
	}

	fprintf(stderr, "dfpkg: unknown command: %s\n", argv[1]);
	usage();
	return 1;
}

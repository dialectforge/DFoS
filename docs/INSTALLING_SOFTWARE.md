# Installing Software on DialectForge OS

DialectForge OS uses a tiered security model enforced by the kernel's LSM
(Linux Security Module). Every piece of software on the system lives in one
of three tiers, and the kernel treats each tier differently.

## The Three Tiers

### Native (Tier 2)
Core OS components compiled into the kernel or shipped with the base image.
These have full seed access and unrestricted dialect permissions. You cannot
install software into this tier — it's reserved for the OS itself.

Examples: kernel modules, dfctl, dfpkg, df_tunnel

### Adopted (Tier 1)
Software that has been verified, relinked, and assigned a scoped seed by
dfpkg. Adopted software runs with its own dialect context — it can encrypt
and decrypt its own memory and IPC, but cannot access other processes'
dialects. This is the normal tier for installed applications.

Examples: user-installed tools, servers, applications

### Quarantine (Tier 0)
Untrusted software. Anything downloaded from the network arrives here first.
Quarantined software runs in a restricted sandbox — no seed access, no
dialect encryption, limited syscalls, no access to other processes' memory
or filesystem regions. The LSM actively blocks privilege escalation attempts.

Examples: unsigned packages, first-run binaries, malware samples for testing

## Installing with dfpkg

The `dfpkg` package manager handles the full adoption pipeline:

```
dfpkg install <url or local path>
```

This runs six stages automatically:

1. **Fetch** — Downloads the package (or copies a local file) into quarantine
2. **Verify** — Computes SHA-256 hash and checks for a GPG signature against
   the trusted keyring at `/etc/dfpkg/trusted.d/`
3. **Relink** — If it's an ELF binary, patches RPATH to use DF system libraries
4. **Assign Seed** — Generates a scoped seed context (e.g., `pkg:nmap:v1.0.0`)
   through the kernel's `/proc/dfctl` interface
5. **Install** — Places the binary in `/opt/df/bin/` (adopted) or keeps it in
   quarantine if unsigned
6. **Audit** — Records metadata in `/var/lib/dfpkg/adopted/` for integrity tracking

### Signed vs Unsigned Packages

If a package has a `.sig` file alongside it, dfpkg verifies the GPG signature
against the trusted keyring. Verified packages are promoted to **Adopted** tier.

If there's no signature, the package stays in **Quarantine** tier. It can still
run, but with restricted permissions. You can later sign and promote it with:

```
dfctl promote <binary>
```

## Managing Packages

```bash
# List all installed packages with their tier and seed scope
dfpkg list

# Show details for a specific package
dfpkg info nmap

# Verify integrity of all installed packages (re-hash and compare)
dfpkg audit

# Remove a package (revokes its seed, deletes binary and metadata)
dfpkg remove nmap
```

## Manual Installation

If you need to install software without dfpkg:

1. Copy the binary anywhere on the filesystem
2. It will automatically run in **Quarantine** tier (the LSM enforces this
   for any unknown binary)
3. To promote it, use `dfctl promote <path-to-binary>`
4. The kernel assigns a seed and moves it to Adopted tier

## What the LSM Blocks in Quarantine

Quarantined software cannot:
- Read or write other processes' memory
- Access dialectfs-encrypted filesystem regions
- Open raw sockets (no network sniffing)
- Load kernel modules
- Access `/proc/dfctl` or `/proc/dialectforge` (no seed manipulation)
- ptrace other processes
- Mount filesystems
- Modify sysctl values

Quarantined software can:
- Read/write its own files in its quarantine directory
- Make outbound network connections (through the Mod Translator)
- Use standard POSIX APIs
- Fork and exec (children inherit quarantine tier)

## For Pentesters

The v1.0 release ships with security tools pre-installed at Adopted tier:

**Traditional:** Metasploit, Nmap, sqlmap, Wireshark/tshark, John the Ripper,
Hashcat, Aircrack-ng

**AI-Powered:** CAI (aliasrobotics), PentAGI (vxcontrol) with Ollama for
local LLM inference

These tools have full Adopted-tier access so you can use them to attack the
OS itself. The challenge: can you break out of the dialect encryption, extract
cleartext from memory, intercept tunnel traffic, or escalate from quarantine
to adopted/native tier?

## Key Paths

| Path | Purpose |
|------|--------|
| `/opt/df/bin/` | Adopted-tier binaries |
| `/var/lib/dfpkg/quarantine/` | Quarantined packages |
| `/var/lib/dfpkg/adopted/` | Package metadata (.meta files) |
| `/etc/dfpkg/trusted.d/` | GPG trusted keyring |
| `/var/cache/dfpkg/` | Download cache |
| `/proc/dfctl` | Kernel dfctl interface |
| `/proc/dialectforge` | System status |
| `/proc/df_mem` | Memory protection status |
| `/proc/df_mem_enable` | Memory protection toggle |

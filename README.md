# DialectForge OS — Kernel

**The first penetration-proof operating system.**

Linux 6.12.12 LTS kernel fork with the DialectForge protocol integrated at the foundational level. Security is not a layer on top — it is the material the system is made of.

*Patent Pending — Provisional Application Filed February 25, 2026*

## Architecture

Traditional OS security is a lock. DialectForge security is an atmosphere.

Malware cannot function on DFOS — not because it was detected, but because the environment is structurally incompatible. Every process runs in a cryptographic dialect derived from a 256-bit seed hierarchy. Dialects cycle. The atmosphere changes. Even malware built specifically for DFOS would fail because the dialect it was built for no longer exists.

**Three-Tier Trust Model:**
- **Native (Tier 0):** Born on DFOS with DF toolchain. Full dialect citizenship.
- **Adopted (Tier 1):** External software promoted through dfpkg. Scoped seed context.
- **Quarantine (Tier 2):** Downloads, email attachments, random binaries. Ephemeral dialect. Can compute, cannot interact with the real system.

**Why Root Doesn't Matter:**
Root is a permission level that doesn't grant dialect knowledge. An attacker with root sees dialect-encoded noise in memory, IPC, and filesystem. Master key to a building where every room speaks a language that changes every hour.

## Kernel Components (~8,900 lines)

| Path | Description |
|------|-------------|
| `df/core.c` | Subsystem init, tier management, dialect lifecycle |
| `df/cipher.c` | AES-256-GCM + HMAC-SHA256 XOR keystream |
| `df/seed.c` | HKDF hierarchical seed derivation |
| `df/cycle.c` | Dialect cycle rotation with jitter |
| `df/quarantine.c` | Quarantine zone lifecycle, crypto-wipe |
| `df/anomaly.c` | Anomaly scoring, emergency rotation |
| `df/integrity.c` | HMAC file attestation, service verification |
| `df/usb_quarantine.c` | USB auto-quarantine, boot device lock |
| `df/adapter.c` | Network adapter, XOR consensus handshake |
| `df/negotiate.c` | Consensus negotiation for shared keys |
| `df/dfctl_proc.c` | `/proc/dfctl` admin interface |
| `df/df_tunnel.c` | Encrypted tunnel daemon |
| `df/dfctl.c` | CLI admin tool |
| `df/dfpkg.c` | Package manager (kernel helper) |
| `df/compress.c` | Emergent compression |
| `df/sysctl.c` | Sysctl tunables |
| `security/df_lsm.c` | Linux Security Module hooks |
| `security/df_quarantine.c` | Tier enforcement helpers |
| `mm/df_mem.c` | Per-process memory page encryption |
| `fs/dialectfs/` | Encrypted filesystem with sector hopping |
| `net/df_proto/` | AF_DIALECTFORGE protocol family |
| `crypto/df_kyber.c` | CRYSTALS-Kyber-768 post-quantum |

## Building

Requires Linux kernel build environment (gcc, make, flex, bison, libelf-dev, libssl-dev).

```bash
git clone https://github.com/dialectforge/DFoS.git
cd DFoS

# The DF subsystem source lives in kernel/
# To build, overlay onto a Linux 6.12.12 source tree:
# cp -r kernel/df/ /path/to/linux-6.12.12/df/
# cp -r kernel/security/ /path/to/linux-6.12.12/security/
# cp -r kernel/mm/ /path/to/linux-6.12.12/mm/
# cp -r kernel/fs/ /path/to/linux-6.12.12/fs/
# cp -r kernel/net/ /path/to/linux-6.12.12/net/
# cp -r kernel/crypto/ /path/to/linux-6.12.12/crypto/
# cp kernel/include/linux/dialectforge.h /path/to/linux-6.12.12/include/linux/

# Then configure and build:
# make menuconfig  # Enable CONFIG_DIALECTFORGE=y
# make -j$(nproc)
```

## Downloads

Pre-built bootable images: [dfos-releases](https://github.com/dialectforge/dfos-releases)

Userspace tools (dfctl, dfpkg, installer): [dfos-tools](https://github.com/dialectforge/dfos-tools)

## License

- **Kernel code:** GPL v2 (see [LICENSE](LICENSES/))
- **DialectForge protocol:** Patent Pending (see [PATENTS](PATENTS))

Free for personal, research, and educational use. Commercial deployment requires a protocol license.

## Author

John Dean Martin — [dialectforge.com](https://dialectforge.com)

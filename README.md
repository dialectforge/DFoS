# DialectForge OS

**The first penetration-proof operating system.**

DialectForge OS is a Linux 6.12 LTS kernel fork where the DialectForge protocol is integrated at the foundational level. Security is not a layer on top — it is the material the system is made of.

*Patent Pending — Provisional Application Filed February 25, 2026*

## The Problem

Every operating system in existence treats security as a layer. Firewalls, encryption, access controls, SELinux, AppArmor — all bolted on top of a fundamentally static, deterministic system. Every penetration test in history exploits that determinism: predictable port numbers, static packet structures, known memory layouts, fixed key storage locations.

The entire cybersecurity industry exists because operating systems are architecturally predictable.

## The Solution

DialectForge OS eliminates the determinism itself.

Every process runs in a cryptographic dialect derived from a 256-bit seed hierarchy. Dialects cycle. Memory is encrypted per-process. IPC channels speak ephemeral languages. The filesystem is noise on disk. Malware cannot function — not because it was detected, but because the environment is structurally incompatible. Like trying to run Windows malware on an iPhone.

DFOS extends this further: even malware built specifically for DFOS would fail, because the dialect has cycled. The atmosphere changed.

## What Root Gets You

Nothing useful. Root is a permission level that doesn't grant dialect knowledge. An attacker with root sees dialect-encoded noise in memory, IPC, and filesystem. Master key to a building where every room speaks a language that changes every hour.

## Three-Tier Trust Model

- **Native (Tier 0):** Built on DFOS with DF toolchain. Full dialect citizenship.
- **Adopted (Tier 1):** External software promoted through dfpkg. Scoped seed context — Firefox gets network access, not your documents.
- **Quarantine (Tier 2):** Downloads, email attachments, random binaries. Ephemeral dialect. Can compute, cannot interact with the real system. Tourists with an expiring visa.

## Downloads

Pre-built bootable images: **[dfos-releases](https://github.com/dialectforge/dfos-releases/releases)**

Flash to USB, boot, done. Credentials: `dfuser` / `dialectforge`

## Kernel Subsystem (~8,900 lines)

This repository contains the GPL v2 kernel source code.

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
| `df/df_tunnel.c` | Encrypted tunnel daemon |
| `security/df_lsm.c` | Linux Security Module (10 hooks) |
| `mm/df_mem.c` | Per-process memory page encryption |
| `fs/dialectfs/` | Encrypted filesystem with sector hopping |
| `net/df_proto/` | AF_DIALECTFORGE protocol family |
| `crypto/df_kyber.c` | CRYSTALS-Kyber-768 post-quantum |

## Building from Source

```bash
git clone https://github.com/dialectforge/DFoS.git
cd DFoS

# Overlay DF source onto Linux 6.12.12 source tree:
cp -r kernel/df/ /path/to/linux-6.12.12/df/
cp -r kernel/security/df_* /path/to/linux-6.12.12/security/
cp -r kernel/mm/df_mem.c /path/to/linux-6.12.12/mm/
cp -r kernel/fs/dialectfs/ /path/to/linux-6.12.12/fs/
cp -r kernel/net/df_proto/ /path/to/linux-6.12.12/net/
cp -r kernel/crypto/df_kyber.c /path/to/linux-6.12.12/crypto/
cp kernel/include/linux/dialectforge.h /path/to/linux-6.12.12/include/linux/

# Configure and build:
make menuconfig  # Enable CONFIG_DIALECTFORGE=y
make -j$(nproc)
```

## Userspace Tools

The userspace tools (dfctl, dfpkg, installer, pentest suite) are proprietary and available separately. Contact dialectforge@gmail.com for commercial licensing or access.

## License

- **Kernel code:** GPL v2
- **DialectForge protocol:** Patent Pending (see [PATENTS](PATENTS))

Free for personal, research, and educational use. Commercial deployment requires a protocol license.

## Links

- **Website:** [dialectforge.com](https://dialectforge.com)
- **Releases:** [github.com/dialectforge/dfos-releases](https://github.com/dialectforge/dfos-releases)
- **Prior Art:** [DialectForge-Native Language Models](https://github.com/dialectforge/dialectforge-prompt)

## Author

John Dean Martin — Ewen, Michigan

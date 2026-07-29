# Ucodectl

**Inspect, validate, build and verify CPU microcode for Linux.**

`ucodectl` is a modern, vendor-neutral toolkit for Intel and AMD microcode:
parse bundles/containers, compare releases, inspect early boot images, build
deterministic early-load CPIO archives, and plan safe filesystem updates.

It is **not** a drop-in replacement for `iucode-tool`. Compatibility with the
legacy CLI is intentionally deferred.

## Status

First version (`0.1.0`). Focus:

| Area | Support |
| ------ | --------- |
| Intel binary bundles + legacy `.dat` | yes |
| AMD `DMA\0` containers + equivalence tables | yes |
| Catalog ingest / diff / manifests | yes |
| Early newc CPIO (build + inspect) | yes |
| UKI `.ucode` section inspection | yes (read-only) |
| Host discovery (`/proc`, sysfs, CPUID) | yes (Linux; graceful off-host) |
| Policy plan + atomic apply | yes |
| Late `/dev/cpu/microcode` loading | **no** (kernel removed it) |
| Network downloads | **no** (package manager owns that) |
| `iucode-tool` flag compatibility | deferred |

## Build

```bash
cargo build --release -p ucodectl
./target/release/ucodectl --help
```

## Quick start

```bash
# Inspect a vendor release tree
ucodectl inspect /lib/firmware/intel-ucode
ucodectl list /lib/firmware/amd-ucode --format json

# Validate structure (checksums, sizes, tables)
ucodectl validate /path/to/microcode.bin --strict

# Match patches to this machine (or an explicit signature)
ucodectl match /lib/firmware/intel-ucode --platform-id 7
ucodectl match ./blobs --signature 0x000806c1 --vendor intel --platform-id 7

# Diff two releases
ucodectl diff /old/intel-ucode /new/intel-ucode

# Build a reproducible early-load CPIO
ucodectl build-early /lib/firmware/intel-ucode /lib/firmware/amd-ucode \
  -o ucode-early.cpio --match-host

# Inspect what is already embedded in an initrd / UKI
ucodectl inspect-boot /boot/initrd.img-$(uname -r)
ucodectl inspect-boot /boot/efi/EFI/Linux/linux.efi --uki

# Plan then apply (apply is explicit and dry-runnable)
ucodectl plan /lib/firmware/intel-ucode --boot /boot/initrd.img
ucodectl apply /lib/firmware/intel-ucode --dry-run
ucodectl apply /lib/firmware/intel-ucode --yes --early-output ucode-early.cpio

# Post-reboot check
ucodectl verify --expect-revision 0x000000b4

# Status uses grouped logical processors by default. Add provenance / raw
# observations for diagnostics, or expand every logical processor.
ucodectl status --verbose --raw
ucodectl status --per-cpu

# Packaging helpers
ucodectl schema
ucodectl completions bash
ucodectl manpages --out-dir man/
```

Stdout is reserved for command results; diagnostics go to stderr.
Every command accepts `--format json`.

`status` distinguishes a missing catalog from a catalog with zero matching
patches, and reports the execution environment separately from microcode
authority. On Windows it reads the active revision from the read-only
`Update Revision` registry value; on WSL2 it reports the revision as
host-managed rather than treating the guest sentinel value as a revision.

## Design principles

1. **Read-only by default** — only `apply` mutates the filesystem.
2. **No network** in the main tool.
3. **Early boot first** — produce artifacts for initrd/UKI loaders, not late loading.
4. **Never invent or “repair” microcode bytes**.
5. **Parsing ≠ trust** — structural validity, authenticity and applicability are separate.
6. **Plan before apply**.
7. **No direct mutation of signed UKIs**.
8. **Deterministic artifacts** (zero timestamps, stable ordering).
9. **Versioned JSON contract** (`ucodectl schema`).
10. **No panic on untrusted input**; hard resource limits everywhere.

## License

Apache-2.0

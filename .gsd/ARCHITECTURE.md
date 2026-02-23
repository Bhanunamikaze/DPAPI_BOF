# ARCHITECTURE.md — SharpDPAPI BOF Port

## Overview
Port of GhostPack/SharpDPAPI from C# to Cobalt Strike Beacon Object Files (BOFs) in pure C.

## Source Analysis (SharpDPAPI C#)

### SharpDPAPI Project (17 commands)
```
Commands/
├── Backupkey.cs       — Retrieve domain DPAPI backup key
├── Blob.cs            — Decrypt arbitrary DPAPI blob
├── Certificate.cs     — Decrypt DPAPI certificate private keys
├── Credentials.cs     — Decrypt Credential files
├── Keepass.cs         — Decrypt KeePass ProtectedUserKey.bin
├── Machinecredentials.cs — Machine credential triage
├── Machinemasterkeys.cs  — Machine masterkey triage
├── Machinetriage.cs      — Full machine triage
├── Machinevaults.cs      — Machine vault triage
├── Masterkeys.cs      — Decrypt user masterkey files
├── PS.cs              — Decrypt PSCredential XML
├── RDG.cs             — Decrypt RDCMan saved passwords
├── SCCM.cs            — SCCM NAA credential decryption
├── Search.cs          — Search for DPAPI blobs
├── Triage.cs          — Full user triage wrapper
└── Vaults.cs          — Decrypt Vault folders

lib/
├── Backup.cs    (161 lines) — LSA backup key retrieval
├── BigInteger.cs (N/A)      — Big integer math (for RSA)
├── Bkrp.cs      (505 lines) — MS-BKRP RPC client (domain key via RPC)
├── Certificate.cs (43 lines)— Cert helper struct
├── Crypto.cs    (348 lines) — AES, 3DES, RSA, HMAC, PBKDF2, Kerberos hash
├── Dpapi.cs     (2203 lines)— Core DPAPI parsing (blobs, vaults, creds, certs, masterkeys)
├── Helpers.cs   (627 lines) — Byte manipulation, encoding, privilege checks
├── Interop.cs   (577 lines) — Win32 P/Invoke: LSA, Registry, NCrypt, Kerberos, tokens
├── LSADump.cs   (195 lines) — LSA secret + boot key extraction
├── PBKDF2.cs    (N/A)       — PBKDF2 implementation
├── Triage.cs    (1223 lines)— File system triage logic
└── Tuple.cs     (N/A)       — .NET 3.5 Tuple polyfill
```

### SharpChrome Project (5 commands)
```
Commands/
├── Backupkey.cs   — Same as SharpDPAPI backupkey
├── Cookies.cs     — Chrome cookie decryption
├── Logins.cs      — Chrome login decryption
├── Statekeys.cs   — Chrome AES state key decryption
└── ICommand.cs

lib/
├── Bcrypt.cs      — BCrypt P/Invoke for AES-GCM
├── Chrome.cs (1050 lines) — Chrome DB reading + DPAPI integration
SQLite/ (embedded C# SQLite library)
```

## Target Architecture (BOF Port)

```
SharpDPAPI-BOF/
├── include/
│   ├── beacon.h              — CS BOF API header
│   ├── bofdefs.h             — DFR macros for Win32 APIs
│   ├── dpapi_common.h        — Shared DPAPI types & function declarations
│   ├── crypto.h              — Crypto function declarations
│   ├── helpers.h             — Helper utilities
│   └── interop.h             — Win32 struct definitions
├── src/
│   ├── common/               — Shared static library source
│   │   ├── crypto.c          — AES, 3DES, HMAC-SHA, PBKDF2, RSA
│   │   ├── dpapi.c           — DPAPI blob/vault/cred/cert/masterkey parsing
│   │   ├── helpers.c         — Byte manipulation, encoding, SID extraction
│   │   ├── interop.c         — Win32 wrappers (LSA, Registry, NCrypt, tokens)
│   │   ├── lsadump.c         — LSA secret + boot key extraction
│   │   └── triage.c          — File system triage logic
│   └── bofs/                 — Individual BOF entry points
│       ├── masterkeys.c
│       ├── credentials.c
│       ├── vaults.c
│       ├── blob.c
│       ├── backupkey.c
│       ├── certificates.c
│       ├── rdg.c
│       ├── keepass.c
│       ├── ps.c
│       ├── triage.c
│       ├── search.c
│       ├── sccm.c
│       ├── machinemasterkeys.c
│       ├── machinecredentials.c
│       ├── machinevaults.c
│       ├── machinetriage.c
│       ├── chrome_logins.c
│       ├── chrome_cookies.c
│       └── chrome_statekeys.c
├── dist/                     — Compiled .o BOF files
├── dpapi.cna                 — Aggressor CNA script
├── Makefile                  — Cross-compilation build system
└── README.md                — Usage documentation
```

## Win32 API Dependency Map

| DLL | Functions | Used By |
|-----|-----------|---------|
| `advapi32.dll` | LsaOpenPolicy, LsaRetrievePrivateData, LsaClose, LsaFreeMemory, LsaNtStatusToWinError | backupkey, lsadump |
| `advapi32.dll` | OpenProcessToken, DuplicateToken, ImpersonateLoggedOnUser, RevertToSelf | helpers (GetSystem) |
| `advapi32.dll` | RegOpenKeyEx, RegQueryInfoKey, RegQueryValueEx, RegCloseKey | lsadump, search |
| `advapi32.dll` | IsTextUnicode | helpers |
| `ncrypt.dll` | NCryptOpenStorageProvider, NCryptImportKey, NCryptExportKey, NCryptSetProperty, NCryptFinalizeKey, NCryptFreeObject | crypto (RSA key export) |
| `cryptdll.dll` | CDLocateCSystem | crypto (Kerberos hash) |
| `crypt32.dll` | CryptUnprotectData | dpapi (blob decryption with /unprotect) |
| `netapi32.dll` | DsGetDcName, NetApiBufferFree | interop (DC discovery) |
| `kernel32.dll` | CloseHandle, GetLastError | general |
| `shlwapi.dll` | PathIsUNC | helpers |
| `rpcrt4.dll` | RPC binding/unbinding functions | bkrp (domain backup key via RPC) |

## Key Design Decisions

1. **Static lib + BOF entry points**: Common code compiled into `dpapi_common.a`, each BOF links against it. The linker strips unused functions, keeping BOFs small.
2. **DFR everywhere**: All Win32 calls go through `KERNEL32$CloseHandle` style macros — no import table.
3. **No CRT dependency**: Use BOF-compatible memory allocation (`KERNEL32$HeapAlloc`) and string functions.
4. **Crypto via Windows APIs**: Use BCrypt/NCrypt for AES-GCM, CNG for hashing where possible; fall back to manual implementations for DPAPI-specific algorithms (PBKDF2, 3DES-HMAC, etc.).

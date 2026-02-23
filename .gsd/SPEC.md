# SPEC.md — Project Specification

> **Status**: `FINALIZED`

## Vision
Port GhostPack's SharpDPAPI (C#) to a collection of Cobalt Strike Beacon Object Files (BOFs) written in C. Each SharpDPAPI command becomes a standalone BOF that can be loaded and executed inline via `beacon_inline_execute`, keeping each compiled BOF under 300KB to avoid inflating beacon size. The BOFs share a common static library for DPAPI parsing, crypto, and Win32 interop.

## Goals
1. **Port all SharpDPAPI commands** — `masterkeys`, `credentials`, `vaults`, `rdg`, `keepass`, `certificates`, `triage`, `machinemasterkeys`, `machinecredentials`, `machinevaults`, `machinetriage`, `ps`, `blob`, `backupkey`, `search`, `sccm` as individual BOFs
2. **Port SharpChrome commands** — `logins`, `cookies`, `statekeys`, `backupkey` (Chrome-specific) as individual BOFs
3. **Create a shared static library** (`dpapi_common`) — DPAPI blob parsing, masterkey decryption, crypto primitives (AES, 3DES, HMAC, PBKDF2, RSA), Win32 API wrappers (LSA, Registry, NCrypt, Token), and helper utilities
4. **Build system with Makefile** — Cross-compile from Linux using MinGW-w64, producing x64 `.o` BOFs
5. **CNA aggressor script** — Loader script that registers all commands and handles argument parsing for Cobalt Strike

## Non-Goals (Out of Scope)
- GUI or interactive UI
- x86 (32-bit) support (can be added later)
- SharpChrome SQLite parsing (requires embedding a SQLite library; deferred to a later phase—may use alternative approach)
- Domain trust / forest-level DPAPI operations beyond what SharpDPAPI already supports
- Managed code / .NET embedding — this is a pure C port

## Users
Red team operators using Cobalt Strike who need to:
- Triage DPAPI-protected secrets on compromised Windows hosts
- Decrypt credentials, vaults, certificates, Chrome logins/cookies
- Operate in-memory without dropping executables to disk

## Constraints
- **Language**: C (C99/C11), compiled with MinGW-w64 for Windows x64
- **BOF size**: Each compiled `.o` must be < 300KB
- **BOF API**: Must use Cobalt Strike's BOF API (`beacon.h`) — `BeaconPrintf`, `BeaconDataParse`, `BeaconFormatAlloc`, etc.
- **Dynamic Function Resolution (DFR)**: All Win32 API calls must use DFR via `DECLSPEC_IMPORT` / `KERNEL32$` / `ADVAPI32$` / `NCRYPT$` notation
- **No CRT**: Cannot rely on standard C runtime; must use BOF-compatible alternatives
- **Reference source**: `Repos/SharpDPAPI/` (C# source) as the canonical reference

## Success Criteria
- [ ] All 16 SharpDPAPI commands compile as individual BOFs under 300KB each
- [ ] All 4 SharpChrome commands compile as individual BOFs under 300KB each
- [ ] CNA script registers all commands with proper argument parsing
- [ ] `masterkeys` BOF can decrypt user masterkeys given a domain PVK backup key
- [ ] `credentials` BOF can decrypt Credential files using decrypted masterkeys
- [ ] `backupkey` BOF can retrieve the domain DPAPI backup key from a DC
- [ ] `triage` BOF runs full user credential + vault + certificate triage
- [ ] All BOFs produce correct BeaconPrintf output matching SharpDPAPI's console output format

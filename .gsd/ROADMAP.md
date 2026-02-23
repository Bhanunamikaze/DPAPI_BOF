# ROADMAP.md

> **Current Phase**: Not started
> **Milestone**: v1.0

## Must-Haves (from SPEC)
- [ ] Shared DPAPI common library (`dpapi_common`) in C
- [ ] 16 SharpDPAPI BOFs compiling under 300KB each
- [ ] 4 SharpChrome BOFs compiling under 300KB each
- [ ] CNA aggressor script for command registration
- [ ] Cross-compilation from Linux via MinGW-w64

## Phases

### Phase 1: Foundation — Build System & Shared Library
**Status**: ⬜ Not Started
**Objective**: Establish the project skeleton, Makefile, BOF headers, and the `dpapi_common` shared static library containing all ported crypto, DPAPI parsing, Win32 interop, and helper code.
**Deliverables**:
- Project directory structure (`src/common/`, `src/bofs/`, `include/`, `dist/`)
- `beacon.h` header (Cobalt Strike BOF API)
- `bofdefs.h` (Dynamic Function Resolution macros)
- `dpapi_common` static lib: `crypto.c/h`, `dpapi.c/h`, `helpers.c/h`, `interop.c/h`, `lsadump.c/h`, `masterkey.c/h`, `triage.c/h`
- Makefile with cross-compilation targets
- Verify: compile the static lib successfully, size check

### Phase 2: Core BOFs — Masterkeys, Credentials, Vaults, Blob
**Status**: ⬜ Not Started
**Objective**: Port the core user-triage commands that form the DPAPI decryption pipeline. These are the foundational BOFs that other commands depend on.
**Deliverables**:
- `masterkeys` BOF — decrypt user masterkey files
- `credentials` BOF — decrypt Credential files
- `vaults` BOF — decrypt Vault folders
- `blob` BOF — decrypt arbitrary DPAPI blobs
- `backupkey` BOF — retrieve domain DPAPI backup key from DC
- Verify: compile each BOF, size < 300KB, functional test with CS

### Phase 3: Extended User Triage BOFs
**Status**: ⬜ Not Started
**Objective**: Port remaining user-context triage commands.
**Deliverables**:
- `certificates` BOF — decrypt DPAPI cert private keys
- `rdg` BOF — decrypt RDCMan saved passwords
- `keepass` BOF — decrypt KeePass ProtectedUserKey.bin
- `ps` BOF — decrypt PowerShell PSCredential XML files
- `triage` BOF — full user triage (credentials + vaults + certs)
- `search` BOF — search for DPAPI blobs in registry/files/folders
- `sccm` BOF — SCCM NAA credential decryption
- Verify: compile each BOF, size < 300KB

### Phase 4: Machine Triage BOFs
**Status**: ⬜ Not Started
**Objective**: Port SYSTEM-level DPAPI triage commands.
**Deliverables**:
- `machinemasterkeys` BOF — decrypt machine masterkeys via DPAPI_SYSTEM LSA secret
- `machinecredentials` BOF — machine credential file triage
- `machinevaults` BOF — machine vault triage
- `machinetriage` BOF — full machine triage (creds + vaults)
- Verify: compile each BOF, size < 300KB

### Phase 5: Chrome BOFs & CNA Integration
**Status**: ⬜ Not Started
**Objective**: Port SharpChrome commands (may require embedding lightweight SQLite or using alternative DB approach) and create the CNA aggressor script.
**Deliverables**:
- `chrome_logins` BOF — decrypt Chrome Login Data
- `chrome_cookies` BOF — decrypt Chrome cookies
- `chrome_statekeys` BOF — decrypt Chrome AES state keys
- `chrome_backupkey` BOF — same as `backupkey` but from SharpChrome context
- `dpapi.cna` — aggressor script registering all BOF commands
- Full README.md with usage documentation
- Verify: compile all BOFs, size < 300KB, end-to-end CNA test

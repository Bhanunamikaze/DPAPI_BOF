# REQUIREMENTS.md

## Format
| ID | Requirement | Source | Status |
|----|-------------|--------|--------|
| REQ-01 | Build system cross-compiles from Linux using MinGW-w64 targeting x64 Windows | SPEC constraint | Pending |
| REQ-02 | Each BOF compiles to a `.o` file under 300KB | SPEC constraint | Pending |
| REQ-03 | All Win32 API calls use Dynamic Function Resolution (DFR) via `KERNEL32$`/`ADVAPI32$`/etc. notation | SPEC constraint | Pending |
| REQ-04 | Shared static library (`dpapi_common.a`) provides DPAPI parsing, crypto, helpers | SPEC goal 3 | Pending |
| REQ-05 | `masterkeys` BOF decrypts user masterkey files using PVK/password/NTLM/credkey/RPC | SPEC goal 1 | Pending |
| REQ-06 | `credentials` BOF decrypts Credential files using masterkey cache | SPEC goal 1 | Pending |
| REQ-07 | `vaults` BOF decrypts Vault folders (Policy.vpol + .vcrd) | SPEC goal 1 | Pending |
| REQ-08 | `blob` BOF decrypts arbitrary DPAPI blobs | SPEC goal 1 | Pending |
| REQ-09 | `backupkey` BOF retrieves domain DPAPI backup key via LSA | SPEC goal 1 | Pending |
| REQ-10 | `certificates` BOF decrypts CAPI/CNG certificate private keys | SPEC goal 1 | Pending |
| REQ-11 | `rdg` BOF decrypts RDCMan.settings passwords | SPEC goal 1 | Pending |
| REQ-12 | `keepass` BOF decrypts KeePass ProtectedUserKey.bin | SPEC goal 1 | Pending |
| REQ-13 | `ps` BOF decrypts PSCredential XML files | SPEC goal 1 | Pending |
| REQ-14 | `triage` BOF wraps credentials + vaults + certs triage | SPEC goal 1 | Pending |
| REQ-15 | `search` BOF searches for DPAPI blobs in registry/files/folders | SPEC goal 1 | Pending |
| REQ-16 | `sccm` BOF decrypts SCCM NAA credentials | SPEC goal 1 | Pending |
| REQ-17 | `machinemasterkeys` BOF decrypts machine masterkeys via DPAPI_SYSTEM | SPEC goal 1 | Pending |
| REQ-18 | `machinecredentials` BOF decrypts machine credential files | SPEC goal 1 | Pending |
| REQ-19 | `machinevaults` BOF decrypts machine vault folders | SPEC goal 1 | Pending |
| REQ-20 | `machinetriage` BOF wraps machine creds + vaults | SPEC goal 1 | Pending |
| REQ-21 | `chrome_logins` BOF decrypts Chrome Login Data | SPEC goal 2 | Pending |
| REQ-22 | `chrome_cookies` BOF decrypts Chrome cookies | SPEC goal 2 | Pending |
| REQ-23 | `chrome_statekeys` BOF decrypts Chrome AES state keys | SPEC goal 2 | Pending |
| REQ-24 | CNA aggressor script registers all commands with proper arg parsing | SPEC goal 5 | Pending |
| REQ-25 | Output matches SharpDPAPI console format via BeaconPrintf | SPEC success criteria | Pending |

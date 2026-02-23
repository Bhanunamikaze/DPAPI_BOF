# DECISIONS.md — Architecture Decision Records

| ID | Decision | Rationale | Date |
|----|----------|-----------|------|
| ADR-01 | Use MinGW-w64 cross-compilation from Linux | Operator works on Linux, targets Windows x64 | 2026-02-24 |
| ADR-02 | Separate BOF per command, shared static lib | Keep each BOF < 300KB; avoid monolithic binary | 2026-02-24 |
| ADR-03 | Dynamic Function Resolution (DFR) for all Win32 calls | Required by BOF execution model — no IAT | 2026-02-24 |
| ADR-04 | Defer SQLite-based Chrome BOFs to Phase 5 | SQLite adds significant binary size; needs investigation for BOF-compatible approach | 2026-02-24 |
| ADR-05 | Pure C (no C++) | Maximum compatibility with BOF loaders, smaller binary size | 2026-02-24 |

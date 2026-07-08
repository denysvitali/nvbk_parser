# OEMNVBK parser completeness gaps

Audit date: 2026-07-08  
Code base: `pkg/nvbk_parser.go`, `pkg/nvbk/*`, `cmd/nvbk_parser/main.go`  
Samples: `resources/*` (5 images + `liboemnvbk_img_helper.so` + incomplete binary templates)

> **Status (2026-07-08, post-fix):** All must-have gaps below are fixed.
> Contiguous TLV walk, u32 `RecordCount`, kinds `0x01`/`0x02`/`0xF1`–`0xF4`,
> VTNV decompress, no false `compressedItemCount` totals, full sample coverage
> tests, `docs/format.md`, and updated 010 templates. This file is kept as the
> historical gap analysis.

## Executive summary

`go test ./...` is green. Header / descriptor / SHA-256 plumbing works. **Payload decode is incomplete** on every sample:

| Sample | Sub-files | Descriptor Σ records (truth) | `list` entries | `list` NV items | Notes |
|--------|-----------|------------------------------|----------------|-----------------|-------|
| `oem_stanvbk-2019-10-23` | 7 | **6558** | 4340 paths | 0 | Stops at non-path records; CountHint u8 truncated (173 vs 1197) |
| `op7t_oem_stanvbk.img` | 6 | **267** | 87 paths | 190 (51 empty Data) | Mixed path + inline NV skipped mid-stream |
| `op8pro_…_stanvbk_trimmed.img` | 10 | **542** | 133 paths | 378 (287 empty Data) | sf6/sf8: no ID-directory zlib |
| `op8pro_…_dycnvbk_trimmed.img` | 1 | **33** | **0** | **0** | Zero-pad false stop @ payload+0x6c during scan |
| `oplusstanvbk.img` | 12 | **518** | **4** | 0 | Stops after first non-path; RF subfiles never walked |

Largest single fix: **contiguous TLV walk of all records** (path + numeric), not “scan then stop at first non-`typeMarker==1`”.

---

## 1. Current pipeline (what works)

### 1.1 Header (`parseHeader`, offsets fixed)

| Offset | Size | Field | Status |
|--------|------|-------|--------|
| 0x00 | 7+1 | Magic `OEMNVBK\0` | ✅ |
| 0x08 | 4 | Version | ✅ stored, not interpreted |
| 0x0c | 1 | Sub-file count | ✅ |
| 0x0d | 4 | Table offset (always `0x1c`) | ✅ |
| 0x11 | 1 | Header flag (`0x00`/`0x01`/`0x02`) | ✅ stored, meaning unknown |
| 0x12 | 3 | Build time YYMMDD BCD-ish | ✅ |
| 0x15 | 1 | Reserved (always 0 in samples) | ✅ |
| 0x16 | 6 | `SignatureOrReserved` | ✅ raw only (`5a2a41` ASCII on oplus) |
| 0x1c…0x1ff | rest | **Descriptor table + zero pad** dumped as `HeaderRemainder` | ⚠️ unparsed blob (table re-read separately) |

### 1.2 Sub-file descriptor (`subFileDescSize = 0x29`)

Observed layout (all samples; matches SHA-256 verify in helper SO):

| Off | Size | Field | Parser today |
|-----|------|-------|--------------|
| 0x00 | **4** | **Record count (u32 LE)** | Only `desc[0]` → `CountHint` (u8) ❌ |
| 0x04 | 2 | Start sector | ✅ |
| 0x06 | 2 | Num sectors | ✅ |
| 0x08 | 32 | SHA-256 of payload | ✅ `PayloadHash` / `Verified` |
| 0x28 | 1 | RF ID | ✅ + `LookupRFIDName` |

Evidence: walking payload TLVs until padding, record count **exactly equals** the u32 at desc[0] for every sub-file of every sample (oem sf1: `0x000004ad` = 1197, not hint 173).

### 1.3 Path entries (`parseEntries`) — partial

Documented layout (when it works):

```
[4:total] [4:tag] [2:type=0x0001] [2:pathLen] [path\0…] [2:sep=0x0002] [2:dataLen] [data]
```

- `dataLen` matches actual payload length in samples; parser **ignores** `dataLen` and takes `raw[dataStart:off+total]`.
- Tag low byte `0x02` = path/file record; RF id often embedded in tag high bytes.

### 1.4 Compressed numeric NV (`parseNVItems` / `FindNVItem`)

Heuristic zlib (`78 9c`) + directory signature (`data[4]==0x34`, count @ byte 7, 24-byte groups). Works for some RF cal on op7t/op8; many directory IDs get **empty `Data`** in `list` while `nv-get` can still find payloads in other blobs/sub-files.

---

## 2. Incomplete / heuristic / unknown paths (code map)

| Location | Behavior | Gap |
|----------|----------|-----|
| `parseHeader` → `HeaderRemainder` | Bytes `0x1c…0x1ff` stored opaque | Includes descriptor table; no structured fields after table (all zeros in samples) |
| `SignatureOrReserved` | 6 raw bytes | Unknown (build id? OEM stamp?). Only oplus non-zero |
| `HeaderFlag` | stored | Meaning of 0/1/2 unknown (age? partition class?) |
| `Version[4]` | stored | Not mapped to format revisions |
| `CountHint` / `desc[0]` | u8 only | Must be **u32 record count** |
| `populateSummary` | `Total=Valid=max(ItemCount)` | **Not read from header**; see §3 |
| `ItemCount` | `max(compressedItemCount, len(Items), CountHint)` | False zlib → **255** on oem RF subfiles |
| `compressedItemCount` | first zlib, return `buf[7]` | False positives on RF path payloads (oem `.dat` zlib) |
| `parseEntries` scan | byte-scan for first path | **Breaks on 12 zero bytes mid-scan** (dyc @ off 108) |
| `parseEntries` after first path | `if typeMarker != 0x0001 { break }` | Drops all later paths **and** all inline NV records |
| “Metadata” comment | “typeMarker != 0x0001 skipped” | **Wrong**: field is NV item ID when tag low byte is `0x01` |
| `dataLen` | not validated | Should assert `dataLen == total - header` |
| `parseNVItems` | best directory only; fill Data once | Empty Data; multi-blob / multi-stream incomplete |
| `findNVItemInBlob` | ID+u16 total + chain check | Misses some records; total max `0x1000` may be tight |
| `LookupNVItemName` | sparse map | Most IDs show as `NV ITEM NNNNN` |
| CLI | info/list/nv-get only | No path extract, no dump-all, no record-type column |
| `pkg/notes.txt` | 6 lines | Stale |
| `resources/binary-templates/*.bt` | `total_items` in header | **Incorrect** vs real layout |
| README | “parser / writer” | Writer not implemented |

---

## 3. Header `Total` / `Valid` — read or derive?

### Claim under test

> Bytes after signature look like `0x4b = 75` on oem → maybe global Total?

### Measurement

```
oem header[0x16:0x1c] = 00 00 00 00 00 00   # SignatureOrReserved
oem header[0x1c]      = 4b 00 00 00         # FIRST DESCRIPTOR u32 count = 75
```

There is **no** separate global Total/Valid field in the 512-byte header after the signature region. Everything from `0x1c` is the descriptor table (count × `0x29`), then zero fill to `0x200`.

Binary templates `bt-1.bt` / `bt-dycnvbk` place `total_items` inside the header; that is an early RE mistake.

### What tests expect today

| Sample | Test `Header.Total` | Source of current value |
|--------|---------------------|-------------------------|
| oem | **255** | `compressedItemCount` false positive (zlib path payload byte7=`0xff`) |
| op7t | 45 | max(CountHint / counts) = 45 |
| op8 sta | 86 | zlib ID-directory `data[7]` |
| op8 dyc | 33 | CountHint of only sub-file |
| oplus | 82 | CountHint of manifest sub-file |

So tests do **not** encode a file-backed Total field. They encode **derived** max item counts, and oem’s 255 is an accident of the zlib heuristic.

### Recommendation

1. **Do not invent header Total/Valid reads** — field does not exist.
2. Prefer:
   - per-subfile `RecordCount` = u32 at desc+0
   - optional summary: `TotalRecords = sum(RecordCount)` or `max(RecordCount)`
   - keep `Valid` / `Verify` as hash-based (“all sub-file hashes OK”) rather than copy of Total
3. When changing semantics, **update tests** (especially `TestParseStaNVBKFileOEM` 255 → real max 1197 or sum 6558, product decision).

---

## 4. True sub-file record format (must-have)

Every sub-file payload is a **contiguous sequence of TLVs**, count = descriptor u32:

### 4.1 Common header (12 bytes minimum)

```
offset 0  u32 total_length   // includes this header
offset 4  u32 tag            // encoding: see below
offset 8  u16 id_or_type
offset 10 u16 length_field
```

### 4.2 Tag low byte

| `tag & 0xff` | Role | `id_or_type` | Rest |
|--------------|------|--------------|------|
| `0x02` | Path / EFS file | must be `0x0001` | pathLen, path, sep `0x0002`, dataLen, data |
| `0x01` | Inline numeric / binary NV | **NV item ID** | `length_field` = data length; data follows |
| `0xf1`–`0xf4`, `0xf3`… | Variant tags (dyc/oplus large blobs, mdb, xml) | often still path or compressed body | needs cataloguing |

Examples (op7t sf0):

- `@0` tag=`10ff0901` id=`4398` → inline NV #4398, 1 byte payload  
- `@44` tag=`10ff0902` type=`1` → path `/nv/item_files/...`

### 4.3 End condition

Zero sector padding after last TLV. **Do not** treat arbitrary 12 zero bytes mid-scan as EOF (dyc bug).

### 4.4 Optional zlib inside TLV payload

RF cal subfiles (op7t/op8/oplus): some TLV payloads begin with zlib. Secondary directory format still useful for bulk ID lists, but **primary** inventory must come from TLV walk.

---

## 5. Concrete sample bugs

### 5.1 `op8pro_…_dycnvbk_trimmed.img` — total decode failure

- Payload starts with inline NV TLVs (ids 0, 1, 0x1bf, …).
- Path TLVs exist at offsets 2724+ (7× `/nv/item_files/mcs/tcxomgr/...`).
- `parseEntries` byte-scans; at **offset 108** hits 12 zero bytes inside a larger record (`total=136` at 88) and **aborts** before any path.
- Result: `list` empty; `ItemCount=33` only from CountHint; zlib streams present but no ID-directory (`data[4]!=0x34`).

### 5.2 `oplusstanvbk.img` — 4 of 518 records

- sf0: 82 TLVs (68 path + 14 inline). Parser emits 4 paths then hits id=`0x15dc` and breaks.
- sf1–11: start with non-path / zlib-wrapped TLVs (`tag&0xff==0x01`). Parser never enters path mode → 0 entries.
- Large path payloads (e.g. `lte_feature_ca.xml` ~272 KiB) contain many `78 9c` sequences → false `compressedItemCount` (78) inflating some `ItemCount`s.

### 5.3 `oem_stanvbk-2019-10-23` — under-count + fake Total 255

- True path counts e.g. sf1: **917** paths + **280** inline NV = 1197 records.
- Parser: 898 paths (stops when first post-run non-path appears after a contiguous path run — actually early stop after first non-path in stream; manifest sf0 only 3 paths).
- `ItemCount=255` from zlib heuristic inside `.dat` path payloads (`buf[7]==0xff`), not from format.

### 5.4 op7t / op8 — empty NV `Data` in `list`

- Directory lists ~38–54 IDs per RF sub-file.
- `parseNVItems` fails to attach payload for many IDs (empty size in `list`).
- `FindNVItem` / `nv-get` often still succeeds (searches all zlib streams + raw across sub-files) — **list and nv-get disagree**.

### 5.5 op8 sf6 / sf8 — zero `Items`

- zlib streams decompress but no `data[4]==0x34` directory.
- Still have 57 TLVs each (path + inline) that TLV walk would capture.

### 5.6 Trimmed images

- Bounds truncate last sub-file; hash verify skipped (expected). Full decode needs untrimmed images for those tails.

---

## 6. Prioritized implementation checklist

### P0 — Must-have (unlock full inventory)

1. **Rewrite payload parser as contiguous TLV walker**  
   - New: `parseRecords(raw []byte) []NVBKRecord` (or extend `parseEntries`).  
   - Consume `total`-sized records from offset 0 until zero pad / EOF.  
   - Branch on `tag&0xff` and `id_or_type`.  
   - **Remove** mid-scan `12×0x00` break during discovery; only stop on aligned EOF padding.

2. **Parse inline numeric TLVs** (`tag&0xff == 0x01`)  
   - `ID = id_or_type`, `Data = payload[0:length_field]`.  
   - Populate `Items` (or unified record list) from **all** sub-files, including oem/dyc/oplus.

3. **Descriptor count as u32**  
   - Rename `CountHint byte` → `RecordCount uint32` (`desc[0:4]`).  
   - `ItemCount` should match walked len (assert in tests).

4. **Stop using `compressedItemCount` for header summary** (or gate strictly on directory signature before reading byte7).  
   - Fixes oem Total 255 lie.

5. **Unify `list` / `nv-get` data sources**  
   - Prefer TLV payloads; use zlib directory only as supplement.  
   - No empty Data when `nv-get` can find bytes.

### P1 — Parser algorithm hardening

6. **Validate path `dataLen`**; store Tag fully; surface tag class in API.  
7. **Catalog tag high bytes** (RF id nibble, flags `0x09`/`0x19`/`0x0d`/`0x40`…).  
8. **Zlib-in-TLV**: if payload starts with zlib, decompress for nested NV directory / secondary items (op7t/op8 RF).  
9. **Alternate zlib headers** (`78 01`, `78 da`) if found.  
10. **Chain / multi-stream ID payload recovery** — fix empty Data for directory-only IDs.  
11. **Large-item total cap** — revisit `0x1000` in `findNVItemInBlob` (op7t item 2730 is 2298 bytes OK, but larger exist).  
12. **HeaderFlag / Version / SignatureOrReserved** RE via `liboemnvbk_img_helper.so` (strings already list `sub nv file number`, hash verify, RF map).

### P2 — CLI output

13. `list`: columns for record kind (`path` / `nv_inline` / `nv_zlib`), full tag, RF sub-file name.  
14. `extract <path|id> -o file` and `extract-all`.  
15. `info --verify` default summary: verified count, truncated sub-files, record totals vs descriptor.  
16. JSON: include hex/base64 payload option; include `RecordCount` u32.  
17. Quiet mode for warnings on trimmed samples.

### P3 — Tests

18. **Golden counts** per sample/sub-file: `RecordCount`, path count, inline NV count (from §5 tables).  
19. dyc: ≥7 tcxomgr paths + 25 inline; not empty.  
20. oplus sf0: 82 records / 68 paths; sf1: 30 records.  
21. oem sf0: 75 records (not 3 paths).  
22. Round-trip: `dataLen` match; SHA-256 still green on full images.  
23. Update Total/Valid tests after summary semantics decision (§3).  
24. `nv-get` vs `list` size consistency for same ID.  
25. Fuzz TLV walker with zero runs inside payloads.

### P4 — Docs

26. Replace `pkg/notes.txt` with this doc + short `docs/format.md` (header, descriptor, TLV).  
27. Fix `resources/binary-templates/*.bt` to match §1–§4.  
28. Document RF ID table provenance (`liboemnvbk_img_helper.so`).  
29. README: remove “writer” or mark unimplemented; document CLI.  
30. Note trimmed sample limitations.

---

## 7. Suggested algorithm (target)

```text
ReadFile:
  parseHeader
  for each descriptor:
    RecordCount = u32(desc[0:4])
    Raw = sectors[start:start+num)
    Verified = sha256(Raw)==hash if full length
    Records = walkTLV(Raw)           # NEW primary
    Entries = filter path records
    Items   = filter inline NV + zlib-derived NV
    assert len(Records) == RecordCount (warn if truncated)
  Summary.TotalRecords = sum(RecordCount)  # or product choice
  Summary.Verify = all Verified
```

```text
walkTLV(raw):
  off = 0
  while off+12 <= len and not isAlignedZeroPad(raw[off:]):
    total = u32(raw[off:])
    if total < 12 or off+total > len: error/break
    tag, id, lfield = ...
    switch tag&0xff:
      case 0x02:
        parse path; validate sep+dataLen
      case 0x01:
        emit NV{ID:id, Data: raw[off+12:off+12+lfield]}
      default:
        emit Unknown{Tag, ID, Raw: raw[off:off+total]}
    off += total
```

---

## 8. Probe log (CLI, 2026-07-08)

```text
go test ./...  → ok

info oem:     Total=255 Valid=255  subfiles=7  (Items column 75/255…)
info op7t:    Total=45  Valid=45   subfiles=6
info op8 dyc: Total=33  Valid=33   subfiles=1  TRUNCATED
info op8 sta: Total=86  Valid=86   subfiles=10 TRUNCATED sf9
info oplus:   Total=82  Valid=82   subfiles=12

list oem:     4340 lines (paths only; missing ~525 paths + all inline NV)
list op7t:    280 lines (paths + partial NV)
list op8 dyc: "No path-based entries or numeric NV items…"
list op8 sta: 516 lines
list oplus:   4 path lines only

nv-get 170 op7t:  296 bytes OK
nv-get 2730 op7t: 2298 bytes OK (but list size 0 for same id in some rows)
nv-get 170 dyc:   513 bytes (raw search hit; not from structured Items)
nv-get 170 oplus: 165 bytes (raw/zlib search; list shows no items)
```

---

## 9. Top 10 action items

1. **TLV walker** — replace break-on-non-path / zero-scan abort (`parseEntries`).  
2. **Inline NV records** — treat `typeMarker` as ID when `tag&0xff==0x01`.  
3. **Descriptor `RecordCount` u32** — replace `CountHint` byte.  
4. **Kill false `compressedItemCount` → 255** — gate or remove from summary.  
5. **Fix dyc zero-pad false EOF** — aligned pad only.  
6. **oplus + oem full path recovery** — falls out of (1).  
7. **Reconcile Items.Data with `FindNVItem`** — list must not show size 0 when data exists.  
8. **Retarget tests** for real record counts; decide Total/Valid semantics (not header fields).  
9. **CLI extract + record-type columns**.  
10. **`docs/format.md` + fix `.bt` templates + expand `notes.txt`**.

---

## 10. Out of scope / later

- Image writer / re-seal SHA-256  
- Full Qualcomm NV item name database  
- Sahara / daemon protocol from helper SO  
- Untrimmed op8 images for last-sub-file hash verify


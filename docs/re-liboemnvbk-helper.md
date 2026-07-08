# Reverse Engineering Report: `liboemnvbk_img_helper.so`

**Target:** `resources/liboemnvbk_img_helper.so`  
**Type:** ELF 64-bit LSB shared object, ARM aarch64, stripped (Android, PIC, full RELRO, stack canary)  
**BuildID (md5):** `97ae913b4e915a7d933eb6b0178d3c39`  
**Size:** 36 312 bytes  
**Date of RE:** 2026-07-08  
**Tools:** radare2 / rabin2, readelf, nm, strings, python3 (struct/hashlib/zlib)

**Related samples (under `resources/`):**

| Sample | Role |
|--------|------|
| `op7t_oem_stanvbk.img` | OnePlus 7T static NVBK |
| `op8pro_o2os_10.5.6.in11ba_stanvbk_trimmed.img` | OnePlus 8 Pro static |
| `op8pro_o2os_10.5.6.in11ba_dycnvbk_trimmed.img` | OnePlus 8 Pro dynamic |
| `oplusstanvbk.img` | Newer OPLUS static |
| `oem_stanvbk-2019-10-23` | Older static (2019-10) |

**Existing Go parser:** `pkg/nvbk_parser.go`, types in `pkg/nvbk/`.

---

## 1. Binary overview

### 1.1 Linked libraries

- `libcutils.so`, `libutils.so`, `liblog.so`, `libc++.so`, `libc.so`, `libm.so`, `libdl.so`

### 1.2 Section map (selected)

| Section | Vaddr | Size | Notes |
|---------|-------|------|-------|
| `.rodata` | `0x1110` | `0xcf0` | Strings + RF ID table |
| `.text` | `0x3000` | `0x3aec` | All logic |
| `.data` | `0x7000` | `0x502` | Partition paths, property names, default RF alias map |
| `.bss` | `0x9000` | `0x89` | Runtime state (parsed subfiles, cached hw/rf, daemon PID) |
| `.gnu_debugdata` | file `0x8471` | `0x360` | Mini-debug XZ ELF (only local names: `oem_get_rf_version`, `SHA256_Transform`, …) |

### 1.3 Exported symbols

| Vaddr | Size | Symbol | Purpose (confidence) |
|-------|------|--------|----------------------|
| `0x3014` | 424 | `oem_mcfg_verify_hash` | SHA-256 verify range `[start+offset, length)` vs expected 32-byte hash. **High** |
| `0x3264` | 800 | `read_oemnvbk_partition_img` | Open stanvbk/dycnvbk partition, parse 0x200 header + 0x29 descriptors, select matching RF subfiles, load sector payloads. **High** |
| `0x37bc` | 320 | `mdm_nvbk_trans_sector_address` | Translate host sector/count → modem Sahara offsets/sizes for SDX50M / SDX55M / SDXPRAIRIE. **High** |
| `0x38fc` | 1056 | `read_oemtmpnvbk_img` | Read prepared `mdm1oemnvbktmp` image (0x2f0-byte Sahara header + OEMNVBK). **High** |
| `0x3d1c` | 2876 | `oem_nvbk_img_helper_main` | Main path: prepare Sahara payload for modem (static + dynamic), write sub NV files, FTM/RF cable handling. **High** |
| `0x4858` | 12 | `oemnvbk_sync_partition` | v1 thin wrapper → v2 with hard-coded `"SDX50M"`. **High** |
| `0x4864` | 756 | `oemnvbk_sync_partition_v2` | Merge dynamic partition updates into target; re-verify SHA-256; rewrite descriptors + sectors. **High** |
| `0x4b58` | 144 | `oemnvbk_add_map_config` | Install OEM RF-id alias map (rows of rfid bytes). **Medium–High** |
| `0x4be8` | 60 | `oemnvbk_prepare_oemvnbktmp` | v1: prepare tmp from stanvbk+dycnvbk with `"SDX50M"`. **High** |
| `0x4c24` | 56 | `oemnvbk_prepare_oemvnbktmp_v2` | v2: same paths but modem type from caller. **High** |
| `0x4c5c` | 280 | `oemnvbk_daemon_kill` | Kill `/vendor/bin/oemnvbkdaemon` by PID/`/proc`. **High** |
| `0x4d74` | 280 | `setup_oemnvbk_daemon_v2` | fork+execve daemon with modem arg. **High** |
| `0x4e8c` | 12 | `setup_oemnvbk_daemon` | v1 wrapper with `"SDX50M"`. **High** |
| `0x4e98` | 28 | `SHA256_Init` | Embedded SHA-256 (not OpenSSL import). **High** |
| `0x4eb4` | 228 | `SHA256_Update` | **High** |
| `0x6910` | 476 | `SHA256_Final` | **High** |
| `0x74f8` | 8 | `oem_hwrfver_bin2hardware_map` | Pointer to RF alias matrix (default → `0x74cc`). **High** |
| `0x7500` | 1 | `oem_hwrfver_bin2hardware_map_rows` | Default `0x0b` (11). **High** |
| `0x7501` | 1 | `oem_hwrfver_bin2hardware_map_cols` | Default `0x04` (4). **High** |

### 1.4 Important non-exported (local) symbols

From disassembly + mini-debugdata:

| Vaddr | Size | Name | Purpose |
|-------|------|------|---------|
| `0x3584` | 568 | `oem_get_rf_version` | Read `vendor.boot.{hw,rf}_version` / `ro.boot.*`, map (hw,rf) → rfid byte via 250-entry table at `.rodata+0x17f8`. |
| `0x4f98` | 6520 | `SHA256_Transform` | Core compression function. |
| `0x31bc` | 168 | `snprintf` fortify wrapper | Used to hex-dump SHA-256. |

### 1.5 Partition / path constants (`.rodata` / `.data`)

| String | Meaning |
|--------|---------|
| `/dev/block/bootdevice/by-name/mdm_oem_stanvbk` | Static OEM NVBK block partition |
| `/dev/block/bootdevice/by-name/mdm_oem_dycnvbk` | Dynamic OEM NVBK block partition |
| `/dev/block/bootdevice/by-name/mdm1oemnvbktmp` | Staging image for modem Sahara |
| `99:/dev/block/bootdevice/by-name/mdm1oemnvbktmp` | dbg-path form (used by “parser dbg path”) |
| `/data/static_nvbk.bin` | Host-side static dump path |
| `/data/dynamic_nvbk.bin` | Host-side dynamic dump path |
| `/firmware/image/mdm9x55` | Default firmware base paths (two slots) |
| `/vendor/bin/oemnvbkdaemon` | Helper daemon binary |
| `/sys/project_info/rf_id_v3` | RF cable present (`'1'` / other) |
| `vendor.boot.hw_version` / `ro.boot.hw_version` | HW SKU property |
| `vendor.boot.rf_version` / `ro.boot.rf_version` | RF SKU property |
| `ro.vendor.factory.mode` / `ro.boot.ftm_mode` | Factory/FTM mode (`ftm_rf`, `ftm_at`) |
| `SDX50M`, `SDX55M`, `SDXPRAIRIE` | Supported modem Sahara profiles |
| `OEMNVBK` | Image magic (null-terminated C string) |

---

## 2. Image constants (recovered)

| Constant | Value | Evidence | Confidence |
|----------|-------|----------|------------|
| Magic | `"OEMNVBK\0"` (8 bytes, `strcmp`) | `read_oemnvbk_partition_img` @ `0x32f8`–`0x3308` | **High** |
| Header size | `0x200` (512) | `malloc(0x200)` + `read(..., 0x200)` @ `0x329c`–`0x32cc` | **High** |
| Sector size | 512 (`<< 9`) | `lsl x1, x8, 9` seek/read throughout | **High** |
| Table offset (typical) | `0x1c` | Samples + `ldur w8, [hdr, #0xd]` | **High** |
| Sub-file descriptor size | `0x29` (41) | `mov w27, #0x29` @ `0x33a8`; `malloc(0x29)` | **High** |
| Max selected subfiles in reader | 2 (static+dynamic pair slots) | `cmp w25, #1` / `b.gt` fail @ `0x3488` | **High** |
| Sahara pre-header (tmp) | `0x2f0` bytes | `read_oemtmpnvbk_img` reads `0x2f0` first | **High** |

---

## 3. Header layout (`OEMNVBKHeader`, 0x200 bytes)

### 3.1 C-like struct

```c
/* Little-endian. First 0x1c bytes are the "active" prefix used by the .so.
 * Remainder of the 0x200 sector is reserved / zero / vendor-specific.
 */
typedef struct __attribute__((packed)) {
    char     magic[8];          /* +0x00: "OEMNVBK\0"  (strcmp) */
    uint8_t  version[4];        /* +0x08: see §3.2 */
    uint8_t  subfile_count;     /* +0x0c: number of descriptors */
    uint32_t table_offset;      /* +0x0d: LE, usually 0x0000001c
                                   NOTE: unaligned uint32 starting at 0x0d */
    uint8_t  header_flag;       /* +0x11: passed to oem_get_rf_version;
                                   0 = formula mode, !=0 = table mode
                                   (samples: 0, 1, 2) */
    uint8_t  build_yy;          /* +0x12: year-2000 style (e.g. 0x13=2019) */
    uint8_t  build_mm;          /* +0x13 */
    uint8_t  build_dd;          /* +0x14 */
    uint8_t  reserved_0;        /* +0x15: 0 in all samples */
    uint8_t  signature_or_tag[6]; /* +0x16: usually 0; oplusstanvbk has ASCII
                                     "5a2a41" (build/tag?) */
    /* +0x1c: start of sub-file descriptor table when table_offset==0x1c */
    uint8_t  rest[0x200 - 0x1c];
} OEMNVBKHeader;
```

### 3.2 Field evidence

| Offset | Access in `.so` | Notes |
|--------|-----------------|-------|
| `+0x00` | `ldr q1,[x22]; strcmp(x21,"OEMNVBK")` | Full 16-byte SIMD copy of prefix into out-struct, then strcmp |
| `+0x0c` | `ldrb w8,[x21,#0xc]` | Loop bound for descriptors; must be non-zero |
| `+0x0d` | `ldur w8,[x21,#0xd]` | Base of descriptor table (file offset) |
| `+0x11` | `ldrb w0,[x21,#0x11]; bl oem_get_rf_version` | Mode / flag for RF resolution |

Code references: `read_oemnvbk_partition_img` `0x32ec`–`0x33a0`.

### 3.3 Version field (`+0x08..+0x0b`)

Observed:

| Sample | version bytes | Kind |
|--------|---------------|------|
| All static samples | `01 00 01 01` | static |
| `…_dycnvbk_…` | `01 00 01 00` | dynamic |

Interpretation (confidence **Medium**):

```text
version[0] = major (1)
version[1] = minor (0)
version[2] = format / generation (1)
version[3] = partition class (1 = static / stanvbk, 0 = dynamic / dycnvbk)
```

The `.so` does **not** branch on these bytes for parsing; it only validates magic + `subfile_count != 0`. Classification is by partition path / caller, not version.

### 3.4 Header vs samples

| Sample | count | flag | build (Y/M/D) | table | sig |
|--------|------:|-----:|---------------|------:|-----|
| op7t stanvbk | 6 | 0 | 19/09/25 | 0x1c | 0 |
| op8pro stanvbk | 10 | 1 | 20/04/26 | 0x1c | 0 |
| op8pro dycnvbk | 1 | 1 | 20/03/21 | 0x1c | 0 |
| oplusstanvbk | 12 | 2 | 24/12/24 | 0x1c | `"5a2a41"` |
| oem_stanvbk-2019 | 7 | 0 | 19/10/08 | 0x1c | 0 |

**Mapping to Go parser:** `pkg/nvbk_parser.go` `parseHeader` matches this layout (magic 8, version 4, count, table LE32, flag, build 3, reserved 1, sig 6). **High** agreement.

---

## 4. Sub-file descriptor layout (41 bytes / `0x29`)

### 4.1 C-like struct

```c
typedef struct __attribute__((packed)) {
    uint32_t entry_count;   /* +0x00: number of top-level records in payload
                               (LE). Go currently uses only low byte as CountHint. */
    uint16_t start_sector;  /* +0x04: absolute sector index (512-byte units)
                               from start of image/partition */
    uint16_t num_sectors;   /* +0x06: length in sectors; 0 → ignored */
    uint8_t  sha256[32];    /* +0x08: SHA-256 of entire sector range
                               (num_sectors * 512 bytes), including trailing
                               zero padding inside those sectors */
    uint8_t  rf_id;         /* +0x28: RF variant id; 0xFF = universal / manifest */
} OEMNVBKSubDesc;           /* sizeof == 0x29 */
```

### 4.2 Byte-by-byte evidence

| Off | Size | Field | Binary evidence | Sample check |
|-----|------|-------|-----------------|--------------|
| 0x00 | 4 | `entry_count` | Copied wholesale with SIMD (`ldp q1,q2,[desc]; ldur q0,[desc,#0x19]`); also written on sync (`ldr w8,[x8]; str w8,[x9]` at `0x49e8`) | op7t[0]=`0x2d`(45), 2019 RF[1]=`0x4ad`(1197) |
| 0x04 | 2 | `start_sector` | `ldrh w8,[desc,#4]; lsl x1,x8,#9; lseek` @ `0x34d8`–`0x34e8` | op7t[0] start=1 |
| 0x06 | 2 | `num_sectors` | `ldrh w8,[x24]` after `add x24,desc,#6`; zero → ignore log @ `0x33bc`–`0x33c0` | op7t[0] nsec=6 |
| 0x08 | 32 | `sha256` | `add x3, desc, #8` passed to verify; memcmp 0x20 | matches `sha256(raw_sectors)` on all complete samples |
| 0x28 | 1 | `rf_id` | `ldrb w3,[desc,#0x28]`; compare to current RF; `0xff` always accepted @ `0x3460` | manifest=`0xff` |

Descriptor stride: `madd x28, index, #0x29, table_base` @ `0x33b4`.

### 4.3 Selection rules (`read_oemnvbk_partition_img`)

For each descriptor `i ∈ [0, subfile_count)`:

1. If `num_sectors == 0` → log `"ignore nv file sector number of which is 0"` and stop iteration.
2. `cur = oem_get_rf_version(header_flag)`.
3. Accept subfile if any of:
   - `rf_id == cur` (exact), or
   - `rf_id` is listed in `oem_hwrfver_bin2hardware_map` row whose first column equals `rf_id` and a later column equals `cur`, or
   - `rf_id == 0xFF` (manifest / common).
4. Else log `"ignore nv file with rf_id %d, cur %d"`.
5. Reader keeps at most **two** accepted subfiles (pair of descriptor pointer + malloc’d payload).

Payload load:

```text
lseek(fd, start_sector << 9, SEEK_SET);
read(fd, buf, num_sectors << 9);
```

### 4.4 Mapping to Go

`parseSubFileDescriptors` uses:

- `desc[4:6]` start, `desc[6:8]` nsec, `desc[8:40]` hash, `desc[0x28]` rfid, `desc[0]` as CountHint.

**Gap:** Go should treat `entry_count` as full `uint32` at `+0` (important for large RF packs like `0x4ad`).

---

## 5. SHA-256 verification

### 5.1 `oem_mcfg_verify_hash` (`0x3014`)

```c
/* Returns 1 on match, 0 on mismatch / invalid args. */
int oem_mcfg_verify_hash(const uint8_t *start,
                         uint32_t offset,
                         uint32_t length,
                         const uint8_t expected[32]);
```

Algorithm (from disassembly `0x307c`–`0x3184`):

1. Reject if `offset` would overflow pointer range (`mvn`/`cmp` guard) → log  
   `"oem_mcfg_verify_hash() invalid start %p offset %x"`.
2. `SHA256_Init` → `SHA256_Update(start + offset, length)` → `SHA256_Final` into 32-byte digest.
3. Hex-dump digest with `"dump sha256 out:"` + `"%02x"` × 32.
4. `memcmp(expected, digest, 0x20)`.
5. Log `"mcfg_auth_verify_hash() hash matches."` or `"…doesn't match!!"`.

PLT stubs inside verify: GOT → `SHA256_Init` (`0x4e98`), `SHA256_Update` (`0x4eb4`), `SHA256_Final` (`0x6910`) — all **local** implementations in this `.so`.

### 5.2 What is hashed?

From `oemnvbk_sync_partition_v2` @ `0x4918`–`0x492c`:

```asm
ldr  x0, [payload_ptr]      ; base of sector data
ldrh w9, [desc, #6]         ; num_sectors
add  x3, desc, #8           ; expected hash
mov  w1, wzr                ; offset = 0
lsl  w2, w9, #9             ; length = num_sectors * 512
bl   oem_mcfg_verify_hash   ; via PLT fcn.00006cf0 → GOT oem_mcfg_verify_hash
```

**Conclusion (confidence High):**

> Hash covers the **entire** sector range:  
> `SHA256( image[start_sector*512 : (start_sector+num_sectors)*512] )`  
> including any zero padding inside the last sectors.  
> It does **not** hash only the live entry stream, and does **not** strip padding.

Cross-check: python `hashlib.sha256(raw_sectors).digest() == desc.sha256` is **True** for every complete subfile in all five sample images (dycnvbk trimmed file is truncated so hash not verified there).

### 5.3 Dynamic update path

`oemnvbk_sync_partition_v2` additionally:

1. Verifies each candidate dynamic subfile’s hash.
2. For matching `rf_id`, `memcmp` old vs new `sha256[32]`.
3. If equal → `"hash is not changed and ignore rf_id %d in dynamic partition."`
4. If different → copy new hash + `entry_count` into the target descriptor, rewrite descriptor at  
   `table_offset + i*0x29`, rewrite payload sectors.

---

## 6. RF ID mapping

### 6.1 Static (hw, rf) → rfid table

- **Location:** `.rodata` `@ 0x17f8`
- **Entry size:** 6 bytes  
  `uint16_t hw; uint16_t rf; uint16_t rfid;` (rfid stored in low byte of third halfword)
- **Count:** 250 (`0xfa`) — loop `cmp x10, #0xfa` in `oem_get_rf_version` @ `0x36ec`
- **Coverage:** `hw ∈ {1..5, 11..15}`, `rf ∈ {11,12,13,14,15, 21..25, 31..35, 41..45, 51..55}`, `rfid = 0x01 … 0xfa`

This is exactly what `pkg/nvbk/names.go` already embeds (`rfIDTable`, comment “offset 0x17f8”).

Lookup algorithm (`oem_get_rf_version`):

1. `property_get("vendor.boot.hw_version")` else `ro.boot.hw_version` → `atoi` → `hw`.
2. Same for `rf_version` → `rf`.
3. Require `1 ≤ hw ≤ 0x7f` and `1 ≤ rf ≤ 0x7f`.
4. If `header_flag != 0`: scan table for matching `(hw,rf)`, return `rfid` byte; cache in `.bss`.
5. If `header_flag == 0`: fallback packing `hw | (rf << 3)` (“unique rfid” log path) — **Medium** confidence on exact semantics; flag=0 images still store table-style rfids in descriptors.
6. On failure: log `"invalid hw,rf info (%s) (%s)!"`, return 0.

Special: `rf_id == 0xFF` in a descriptor always means “apply for all / manifest”.

### 6.2 Runtime alias map (`oem_hwrfver_bin2hardware_map`)

- Default pointer relocates to `0x74cc` (`.data`), rows=`0x0b`, cols=`0x04`.
- Default bytes at `0x74cc` look like pre-seeded rfid clusters (e.g. `7e 7e 7e 7e | e2 e2 e2 e2 | …`).
- Used only when exact rfid match fails: find row where `map[row][0] == subfile.rf_id`, then accept if any `map[row][1..cols-1] == current_rf`.
- `oemnvbk_add_map_config(ptr, n)` rebuilds a heap map from OEM-supplied lists (log `"add oem mapping ..."`).

### 6.3 FTM / RF cable

In `oem_nvbk_img_helper_main`:

- Factory mode properties select RF mode codes `0`, `0x11`, `0x13`.
- `/sys/project_info/rf_id_v3` first byte `'1'` → cable connected.

These affect modem transmit selection, not on-disk format.

### 6.4 Sample RF IDs

| Sample | Subfile RF IDs |
|--------|----------------|
| op7t | `ff, 59, 5c, 5d, 65, 69` → hw/rf pairs via table (e.g. `0x59` = hw=4,rf=34) |
| op8pro stan | `ff, 7f, 80, 81, 82, b1, ca, cb, …` |
| oplusstan | `ff, 01..0b` (low ids — early table entries) |
| 2019 | `ff, 0f, 15, 1f, 33, 34, 35` |

---

## 7. Payload / entry formats (inside a subfile)

**Important:** `liboemnvbk_img_helper.so` does **not** parse path entries, zlib, or NV item directories. It treats payloads as opaque sector blobs (copy, hash, Sahara xfer).  
Payload structure below is recovered from **samples** + existing Go heuristics, not from this `.so`.

### 7.1 Record stream (common)

Subfile body is a contiguous sequence of variable-length records until zero padding:

```c
typedef struct __attribute__((packed)) {
    uint32_t total_size;   /* includes this 4-byte field */
    uint8_t  type;         /* record class — see below */
    uint8_t  subtype;      /* 0x09 / 0x0d / 0x19 / 0x29 / … */
    uint8_t  rf_id;        /* mirrors parent descriptor (or 0xff) */
    uint8_t  flags;        /* 0x10, 0x18, 0x50, … */
    uint8_t  body[total_size - 8];
} OEMNVBKRecord;
```

Tag dword at `+4` is the 4-tuple `(type, subtype, rf_id, flags)` in little-endian memory order.

### 7.2 Type `0x02` — path / EFS entry

```c
/* body layout after the 8-byte header */
uint16_t type_marker;     /* must be 0x0001 */
uint16_t path_len;        /* includes terminating NUL */
char     path[path_len];  /* e.g. "/nv/item_files/..." */
uint16_t separator;       /* 0x0002 */
uint16_t data_len;
uint8_t  data[data_len];
/* total_size == 8 + 2+2 + path_len + 2+2 + data_len  (with possible pad) */
```

Matches Go `parseEntries` (which also requires `type` low byte of tag `== 0x02`).

Seen heavily in:

- Manifest subfiles (`rf_id=0xff`) on all static images
- Trailing path tails after compressed RF blobs (e.g. tcxomgr calibration paths)

### 7.3 Type `0x01` — numeric / compact NV item

```c
/* after 8-byte header */
uint16_t nv_id;           /* LE Qualcomm NV item id */
uint8_t  data[total_size - 10];
```

Examples (op7t manifest):

- `total=0x0d`, tag=`01 09 ff 10`, `nv_id=0x112e` (4398)
- dycnvbk stores many classic items (447 `bd_addr`, 1943 `meid`, 4678 `wlan_mac`, 6853+ OEM items)

### 7.4 Compressed / large blobs (`type` `0x01`/`0x0d`/`0xf1`/`0xf3` + zlib)

Large records often embed:

1. Optional **`VTNV`** magic at body offset +4 (file offset +12 from record start).
2. **zlib** stream (`78 9c …`) shortly after (offsets observed: +12, +18, +20, +26 from record start).

Decompressed content variants:

| Pattern | Meaning | Seen in |
|---------|---------|---------|
| ID directory: byte4=`0x34`, count at byte7, then 24-byte groups of 4×(4 zero + u16 id) | RF NV item index | op8pro stan RF |
| Chain of `u16 id + u16 total + payload` | Item payloads | Go `findNVItemInBlob` |
| Nested config blobs | Various | oplusstan trailing zlib |

**Go coverage:** `parseNVItems` / `compressedItemCount` / `FindNVItem` implement the zlib + directory heuristics. They are sample-driven, not present in the `.so`.

### 7.5 Descriptor `entry_count` vs records

`entry_count` is a **declared** top-level record count. Empirical match is good for small manifests; large RF packs use multi-thousand counts (2019: 1197). Parser should not assume `entry_count == len(parsed_paths)`.

---

## 8. Sahara / modem transfer (`mdm_nvbk_trans_sector_address`)

```c
/* Returns 1 on success, 0 on failure.
 * Writes *out_offset and *out_size (host-relative addresses for modem image).
 */
int mdm_nvbk_trans_sector_address(
    int part_index,          /* 0 or 1 (static vs dynamic slot) */
    uint32_t start_sector,
    uint32_t num_sectors,
    uint32_t *out_offset,
    uint32_t *out_size,
    const char *modem_type   /* "SDX50M" | "SDX55M" | "SDXPRAIRIE" */
);
```

Rules (from `0x37bc`–`0x38c8`):

| Modem | Memory cap | Non-zero start | Notes |
|-------|------------|----------------|-------|
| `SDX50M` | `0x100000` | `offset = (start<<9) \| 0xf0`, size = `(start+num)<<9 + 0x2f0` (bounds-checked) | 1 MiB window |
| `SDX55M` / `SDXPRAIRIE` | `0x200000` | same formula with 2 MiB cap | |
| start==0 specials | — | part0 → off=`0x210`, size=`0x6e`; part1 → off=`0x27e`, size=`0x6e` | header-only stubs |

`read_oemtmpnvbk_img` reads the first **`0x2f0`** bytes of the tmp image (Sahara header), then locates the OEMNVBK blob via translated offsets.

`oem_nvbk_img_helper_main` writes a composite Sahara image: header prefix, up to two subfile descriptors (`0x29` each), padding, then payload sectors — logging `"1st/2nd/3rd/4th/5th offest in %s: 0x%x"` (typo “offest” is in the binary).

---

## 9. v1 vs v2 API surface

| v1 | v2 | Difference |
|----|----|------------|
| `oemnvbk_sync_partition` | `oemnvbk_sync_partition_v2` | v1 is 12-byte trampoline that forces modem=`"SDX50M"` then jumps into v2 |
| `oemnvbk_prepare_oemvnbktmp` | `oemnvbk_prepare_oemvnbktmp_v2` | Same partition paths; v1 hardcodes `"SDX50M"`, v2 takes modem string in `x0` |
| `setup_oemnvbk_daemon` | `setup_oemnvbk_daemon_v2` | v1 hardcodes `"SDX50M"`; v2 accepts modem arg, fork/exec `/vendor/bin/oemnvbkdaemon` |

**Format implication:** v1/v2 are **runtime / modem-profile** differences, not different on-disk OEMNVBK layouts. On-disk format is shared.

Prepare always uses:

```text
stan = /dev/block/bootdevice/by-name/mdm_oem_stanvbk
dyc  = /dev/block/bootdevice/by-name/mdm_oem_dycnvbk
tmp  = /dev/block/bootdevice/by-name/mdm1oemnvbktmp
```

---

## 10. In-memory structures (runtime, not on disk)

From `read_oemnvbk_partition_img` / main:

```c
/* Per selected subfile — 16-byte slot (2 pointers) */
struct LoadedSub {
    OEMNVBKSubDesc *desc;   /* malloc(0x29), copy of descriptor */
    uint8_t        *data;   /* malloc(num_sectors << 9) */
};

/* Header shadow used as strcmp target — first 0x1c-ish bytes of OEMNVBKHeader */
```

`.bss` also caches last `(hw, rf, rfid)` from `oem_get_rf_version` and daemon PID at `0x7260`-region / `0x9000+`.

---

## 11. What the `.so` does *not* implement

These are **absent** from `liboemnvbk_img_helper.so` (no strings, no code):

- Path-entry parsing / EFS walk  
- zlib inflate / deflate  
- NV item ID directory parsing  
- Writing / building OEMNVBK images from scratch (only merge/sync of existing blobs)  
- RSA / authenticated boot of the image (only SHA-256 integrity of subfile sectors)  
- Interpretation of `version[]` or `signature_or_tag[6]`

Payload decoding must continue to live in host tools (this repo’s Go parser).

---

## 12. Mapping findings → samples → Go parser

| Concern | `.so` | Samples | Go status |
|---------|-------|---------|-----------|
| Magic / 0x200 header | Yes | All | OK |
| Descriptor 0x29 | Yes | All | OK (entry_count only low byte) |
| SHA-256 whole sectors | Yes | Verified True | OK (`sha256.Sum256(raw)`) |
| RF id 0xff manifest | Yes | All | OK (`LookupRFIDName`) |
| RF table 0x17f8 | Yes | Used | OK (`names.go`) |
| Path entries type 0x02 | No (opaque) | Yes | Partial (`parseEntries`) |
| zlib / VTNV / ID dir | No | Yes | Partial (`parseNVItems`) |
| Numeric type 0x01 records | No | Yes (esp. dycnvbk) | Partial via scan |
| Sahara 0x2f0 | Yes | Not in raw partition dumps | N/A for offline parse |
| Dynamic hash merge | Yes | dycnvbk sample | N/A offline |

---

## 13. Confidence summary

| Finding | Confidence |
|---------|------------|
| Header layout §3 | **High** |
| Descriptor layout §4 | **High** |
| Sector size 512, hash whole range §5 | **High** |
| RF table + 0xff special §6.1 | **High** |
| Alias map semantics §6.2 | **Medium–High** |
| header_flag=0 packing formula | **Medium** |
| version[3] static/dynamic | **Medium** |
| signature_or_tag meaning (`5a2a41`) | **Low** |
| Path / NV / zlib payload layouts §7 | **Medium–High** (samples, not `.so`) |
| VTNV container internals | **Low–Medium** |
| entry_count exact semantics | **Medium–High** (count of top-level records) |

---

## 14. Remaining unknowns / open gaps

1. **`version[0..2]`** full meaning beyond major=1; whether any writer/reader enforces them.  
2. **`signature_or_tag[6]`** — only non-zero on `oplusstanvbk.img` (`"5a2a41"`); possibly build fingerprint, not a crypto signature (no verify code in `.so`).  
3. **`header_flag` values 1 vs 2** — both non-zero take table path; finer meaning unknown (SKU family? dual-SIM?).  
4. **Record `subtype` / `flags`** enumeration (0x09 vs 0x0d vs 0x19, flags 0x10 vs 0x18 vs 0x50).  
5. **VTNV** container full schema (size fields, nested item count, relationship to zlib members).  
6. **Type `0xf1` / `0xf3`** large compressed records — exact header before zlib.  
7. **ID-directory** layout after zlib (byte4=`0x34`) — Go heuristic works on op8pro; needs formalization against more samples.  
8. **Default alias map** at `0x74cc` row meanings (device-specific OEM config?).  
9. **Sahara header** 0x2f0-byte structure (fields beyond size constants) — only partially constrained by `mdm_nvbk_trans_sector_address`.  
10. **Who calls `oem_mcfg_verify_hash` at image build time** — this library verifies at sync; image *creation* is external (factory tooling).  
11. **dycnvbk record mix** — many type-0x01 numeric items + sparse zlib; relationship to static RF packs unclear.  
12. **Maximum subfile_count / image size** — only soft limits from modem memory caps (1–2 MiB Sahara window), not from header.

---

## 15. Recommended parser follow-ups (not done in this RE pass)

1. Promote `CountHint byte` → `EntryCount uint32` from `desc[0:4]`.  
2. Optionally parse type-0x01 numeric records without requiring zlib.  
3. Document VTNV + multi-zlib streams as a dedicated codec once more samples collected.  
4. Treat `version[3]==0` as dynamic partition marker in UI/summary.  
5. Keep hash verification as whole-sector (already correct).

---

## Appendix A — Key code xrefs (vaddr)

| Topic | Addresses |
|-------|-----------|
| Read 0x200 header | `0x329c`–`0x3308` |
| Descriptor loop / 0x29 | `0x33a8`–`0x3524` |
| Sector seek/read | `0x34d4`–`0x3510` |
| RF filter + 0xff | `0x33c4`–`0x3488` |
| Hash API | `0x3014`–`0x3184` |
| Hash use (sync) | `0x4918`–`0x4934` |
| RF table scan | `0x36c0`–`0x36f4` (table base `0x17f8`) |
| Modem type switch | `0x37fc`–`0x3850`, `0x3d50`–`0x3de8` |
| Prepare v1/v2 | `0x4be8`, `0x4c24` |
| Daemon v2 | `0x4d74`–`0x4e88` |

## Appendix B — Example descriptor (op7t subfile 0)

```text
offset 0x001c:
  2d 00 00 00   entry_count = 45
  01 00         start_sector = 1
  06 00         num_sectors  = 6
  83 a1 ce 3e 2b 92 2d ca a6 ad 72 9d 68 77 fb fa
  53 f4 30 12 9e 12 b7 e0 18 42 3e 21 08 7c 28 71   sha256
  ff            rf_id = 0xFF (manifest)

payload @ 0x200, length 0xC00
sha256(payload) == descriptor hash  ✓
```

## Appendix C — Build identity

```text
file: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV),
      dynamically linked, BuildID[md5/uuid]=97ae913b4e915a7d933eb6b0178d3c39, stripped
Android note present (.note.android.ident)
```

---

*End of report. Production parser code was not modified in this RE pass.*

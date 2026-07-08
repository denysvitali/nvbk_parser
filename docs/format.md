# OEMNVBK image format

Parser for Oppo / OnePlus / OPLUS `static_nvbk` and `dynamic_nvbk` partitions
(`OEMNVBK` images). Layout recovered from sample images and
`resources/liboemnvbk_img_helper.so` (Android aarch64).

## Overview

```
┌──────────────────────────── sector 0 (0x200) ────────────────────────────┐
│ Header prefix (0x1c) │ Descriptor table (N × 0x29) │ zero pad to 0x200   │
└──────────────────────────────────────────────────────────────────────────┘
┌── sub-file 0 (start_sector × 512) ───────────────────────────────────────┐
│ TLV record × record_count │ zero pad to num_sectors × 512                │
└──────────────────────────────────────────────────────────────────────────┘
 … sub-file 1 … N-1
```

- Endianness: little-endian
- Sector size: 512 bytes
- Magic: `OEMNVBK\0` (8 bytes)

## Header (512 bytes)

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0x00 | 8 | `magic` | `"OEMNVBK\0"` |
| 0x08 | 4 | `version` | STA often `01 00 01 01`; DYC `01 00 01 00` |
| 0x0c | 1 | `sub_file_count` | N descriptors |
| 0x0d | 4 | `table_offset` | always `0x1c` in known samples (unaligned u32) |
| 0x11 | 1 | `header_flag` | `0x00` older, `0x01` OP8-era, `0x02` newer OPLUS; also RF-resolution mode in helper SO |
| 0x12 | 3 | `build_time` | `YY MM DD` binary (e.g. `0x13 0x0a 0x08` → 2019-10-08) |
| 0x15 | 1 | `reserved` | `0` in samples |
| 0x16 | 6 | `signature_or_reserved` | usually zeros; `oplusstanvbk` has ASCII `5a2a41` |
| 0x1c | … | descriptor table | when `table_offset == 0x1c` |

**No global Total/Valid field exists.** Those values in the CLI are derived:
`Total = Σ record_count`, `Valid = Σ record_count` for SHA-verified sub-files.

## Sub-file descriptor (41 = 0x29 bytes)

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0x00 | 4 | `record_count` | **u32 LE** — number of TLV records in payload |
| 0x04 | 2 | `start_sector` | payload file offset = `start_sector * 512` |
| 0x06 | 2 | `num_sectors` | payload length = `num_sectors * 512` |
| 0x08 | 32 | `sha256` | SHA-256 of entire payload including trailing zero pad |
| 0x28 | 1 | `rf_id` | `0xff` = manifest/common; else maps to `(hw, rf)` via table in helper SO |

## Sub-file payload (TLV stream)

Exactly `record_count` records, then zero-padded to `num_sectors * 512`.

### Common record header (12 bytes minimum)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0x00 | 4 | `total` — full record size including this field |
| 0x04 | 1 | `kind` |
| 0x05 | 1 | `attr` (generation / attribute: `0x09`, `0x0d`, `0x19`, `0x29`, …) |
| 0x06 | 1 | `rfid` — matches owning sub-file RF ID |
| 0x07 | 1 | `flags` (`0x10` normal, `0x50` VTNV container, `0x18` newer path, …) |
| 0x08 | 2 | `field_a` — NV id **or** path marker `0x0001` |
| 0x0a | 2 | `field_b` — data length **or** path length |
| 0x0c | … | payload |

Tag as u32 LE = `kind | attr<<8 | rfid<<16 | flags<<24`.

### kind = 0x01 / 0xF1 / 0xF3 — numeric / binary item

```
[u32 total][tag][u16 nv_id][u16 data_len][data…]
```

- For classic `0x01`, `data_len == total - 12`.
- Payload may be raw bytes, raw zlib (`78 9c…`), or **VTNV** wrapper:

```
"VTNV" | u16 version | u16 field | zlib…
```

- `0xF3` may insert a short lead (`u16`s) before VTNV/zlib; outer `total` still
  frames the record so the stream remains walkable.

### kind = 0x02 / 0xF2 / 0xF4 — EFS path entry

```
[u32 total][tag][u16 type=0x0001][u16 path_len]
[path bytes…][u16 sep=0x0002][u16 data_len][data…]
```

Paths look like `/nv/item_files/...`.

### End of stream

Trailing bytes after the last record are **zero** (sector padding). Do not treat
interior zero runs as EOF.

## RF ID table

250 entries of `(hw_u16, rf_u16, rfid_u8)` live in
`liboemnvbk_img_helper.so` `.rodata` @ `0x17f8` (6 bytes each). Exposed in Go as
`nvbk.LookupRFIDName`. Special: `rfid == 0xff` → `"manifest"`.

## Nested RFNV directory (inside VTNV/zlib)

Some decompressed RF cal blobs use:

```
header[16]: byte4 == 0x34, byte7 == group_count
then group_count × 24 bytes: 4 × (u32 zero + u16 id)
```

Item payloads appear as chains of `[u16 id][u16 total][data]` elsewhere in the
same blob. This is **nested** content, not the outer OEMNVBK framing.

## Sample coverage (full decode)

| Sample | Flag | Subs | Records (Σ) | Notes |
|--------|-----:|-----:|------------:|-------|
| `oem_stanvbk-2019-10-23` | 0x00 | 7 | 6558 | Full, all hashes OK |
| `op7t_oem_stanvbk.img` | 0x00 | 6 | 267 | Full + VTNV RF cal |
| `op8pro_…_dycnvbk_trimmed.img` | 0x01 | 1 | 33 | Trimmed; mostly numeric |
| `op8pro_…_stanvbk_trimmed.img` | 0x01 | 10 | 552 | Last sub-file truncated |
| `oplusstanvbk.img` | 0x02 | 12 | 518 | Newer flag + signature tag |

## CLI

```bash
nvbk_parser info --verify FILE    # header + per-subfile coverage
nvbk_parser list FILE             # path entries + numeric items
nvbk_parser records FILE          # every TLV record
nvbk_parser nv-get ID FILE        # extract one NV item by id
```

# nvbk_parser

Parser for Oppo / OnePlus / OPLUS `static_nvbk` and `dynamic_nvbk` partitions
(`OEMNVBK` images). Fully decodes every TLV record in the known sample set.

## Build

```bash
go build -o nvbk_parser ./cmd/nvbk_parser/
```

## Usage

```bash
# Header + sub-file table (SHA-256 verify, coverage %)
./nvbk_parser info --verify resources/op7t_oem_stanvbk.img

# Path entries and numeric NV items
./nvbk_parser list resources/oplusstanvbk.img
./nvbk_parser list -o json resources/oem_stanvbk-2019-10-23 | head

# Full TLV record dump
./nvbk_parser records resources/op8pro_o2os_10.5.6.in11ba_dycnvbk_trimmed.img

# Extract one numeric NV item by ID
./nvbk_parser nv-get 550 resources/op7t_oem_stanvbk.img
```

## Format

See **[docs/format.md](docs/format.md)** for the complete binary layout.

Quick facts:

- Header 512 bytes, magic `OEMNVBK\0`
- Sub-file descriptors 41 bytes (`record_count` is **u32**, not u8)
- Payload = contiguous TLV records + zero pad; kinds `0x01`/`0x02`/`0xF1`–`0xF4`
- SHA-256 per sub-file covers the full sector-aligned payload

## Reverse-engineering notes

| Doc | Content |
|-----|---------|
| [docs/format.md](docs/format.md) | Authoritative wire format |
| [docs/re-liboemnvbk-helper.md](docs/re-liboemnvbk-helper.md) | RE of `liboemnvbk_img_helper.so` |
| [docs/re-samples-decode.md](docs/re-samples-decode.md) | Per-sample coverage tables |
| [docs/re-parser-gaps.md](docs/re-parser-gaps.md) | Historical gap analysis (pre-fix) |
| [pkg/notes.txt](pkg/notes.txt) | Short layout cheat sheet |

## Tests

```bash
go test ./...
```

Samples live under `resources/`. Trimmed OP8 images intentionally fail hash
verify on the last sub-file.

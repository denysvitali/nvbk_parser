package nvbk

// NVBKHeader holds the parsed metadata from the 512-byte OEMNVBK header.
//
// There is no file-backed global Total/Valid field; Total/Valid/Verify are
// derived after parsing (see parser populateSummary).
type NVBKHeader struct {
	Magic               string
	Version             [4]byte
	SubFileCount        int
	TableOffset         uint32
	HeaderFlag          byte
	BuildTime           string
	ReservedAfterBuild  [1]byte
	SignatureOrReserved [6]byte
	HeaderRemainder     []byte `json:"-"`
	// Total is the sum of RecordCount across all sub-files.
	Total int
	// Valid is the sum of RecordCount for sub-files whose SHA-256 verified.
	Valid int
	// Verify is true when every complete (non-truncated) sub-file hash matches.
	Verify bool
}

// Record types observed in OEMNVBK sub-file payloads.
// Extended kinds 0xF1-0xF4 reuse the low nibble: 0x1 = item, 0x2 = path.
const (
	RecordTypeItem byte = 0x01
	RecordTypePath byte = 0x02

	RecordTypeItemExt1 byte = 0xF1 // large numeric / VTNV
	RecordTypePathExt1 byte = 0xF2 // large path
	RecordTypeItemExt2 byte = 0xF3 // large numeric (lead u16s + zlib/VTNV)
	RecordTypePathExt2 byte = 0xF4 // large path (rare)
)

// IsPathType reports whether a record kind encodes an EFS path entry.
func IsPathType(t byte) bool {
	return t == RecordTypePath || t == RecordTypePathExt1 || t == RecordTypePathExt2 || (t&0x0f) == 0x02
}

// IsItemType reports whether a record kind encodes a numeric/binary NV item.
func IsItemType(t byte) bool {
	return t == RecordTypeItem || t == RecordTypeItemExt1 || t == RecordTypeItemExt2 || (t&0x0f) == 0x01
}

// NVBKRecord is one contiguous TLV record inside a sub-file payload.
//
// Wire layout (little-endian):
//
//	u32 total           // size of whole record including this field
//	u8  type            // kind (0x01/0x02/0xF1-0xF4, …)
//	u8  attr            // attribute / generation (0x09, 0x0d, 0x19, 0x29, …)
//	u8  rfid            // copy of owning sub-file RF ID (0xff = manifest)
//	u8  flags           // 0x10 normal, 0x50 VTNV container, 0x18 newer path, …
//	… type-specific payload …
type NVBKRecord struct {
	Offset int
	Total  int
	Type   byte
	Attr   byte
	RFID   byte
	Flags  byte
	// ItemID is set for item-type records.
	ItemID uint16
	// Name is the EFS path for path-type records.
	Name string
	// Data is the item/file payload bytes (not including the 12-byte header).
	Data []byte
	// VTNV is true when the payload is a VTNV zlib container.
	VTNV bool
	// Compressed holds decompressed VTNV/zlib payload when available.
	Compressed []byte `json:"-"`
}

// NVBKEntry represents a path-based EFS entry.
type NVBKEntry struct {
	Name string
	Tag  uint32
	Data []byte
}

// NVBKItem represents a numeric NV item (ID-based).
type NVBKItem struct {
	ID   uint16
	Name string
	Data []byte
}

// NVBKSubFile describes one sub-file descriptor and its decoded contents.
//
// Descriptor layout (0x29 bytes):
//
//	u32 record_count | u16 start_sector | u16 num_sectors | 32 sha256 | u8 rf_id
type NVBKSubFile struct {
	Index int
	// RecordCount is the u32 at descriptor offset 0 (expected TLV count).
	RecordCount uint32
	StartSector uint16
	NumSectors  uint16
	RFID        byte
	PayloadHash []byte `json:"-"`
	Verified    bool
	Raw         []byte `json:"-"`
	// Records is the full contiguous TLV decode of the sub-file payload.
	Records []NVBKRecord
	// Entries are path-type records.
	Entries []NVBKEntry
	// Items are numeric NV items (inline + nested VTNV/zlib recoveries).
	Items []NVBKItem
	// ItemCount equals RecordCount when the walk matches; otherwise walked count.
	ItemCount int
	// BytesCovered is how many payload bytes were consumed by TLV records.
	BytesCovered int
}

// NVBKFile is the top-level parsed representation of an OEMNVBK image.
type NVBKFile struct {
	Header   NVBKHeader
	SubFiles []NVBKSubFile
}

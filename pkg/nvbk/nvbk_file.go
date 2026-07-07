package nvbk

// NVBKHeader holds the parsed metadata from the 512-byte OEMNVBK header.
type NVBKHeader struct {
	Magic        string
	Version      [4]byte
	SubFileCount int
	TableOffset  uint32
	BuildTime    string
	Total        int
	Valid        int
	Verify       bool
}

// NVBKEntry represents a single NV item / file extracted from a sub-file.
type NVBKEntry struct {
	Name string
	Tag  uint32
	Data []byte
}

// NVBKItem represents a numeric NV item (ID-based) extracted from a sub-file.
type NVBKItem struct {
	ID   uint16
	Name string
	Data []byte
}

// NVBKSubFile describes one sub-file descriptor and its decoded contents.
type NVBKSubFile struct {
	Index       int
	StartSector uint16
	NumSectors  uint16
	RFID        byte
	CountHint   byte
	Raw         []byte
	Entries     []NVBKEntry
	Items       []NVBKItem
	ItemCount   int
}

// NVBKFile is the top-level parsed representation of an OEMNVBK image.
type NVBKFile struct {
	Header   NVBKHeader
	SubFiles []NVBKSubFile
}

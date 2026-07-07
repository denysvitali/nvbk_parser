package nvbk_parser

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/denysvitali/nvbk_parser/pkg/nvbk"
	"github.com/sirupsen/logrus"
)

var Log = logrus.New()

const (
	headerSize      = 0x200
	subFileDescSize = 0x29
)

// ReadFile parses an OEMNVBK image and returns its structure.
func ReadFile(path string) (*nvbk.NVBKFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %w", path, err)
	}

	if len(b) < headerSize {
		return nil, errors.New("file is too small to contain an OEMNVBK header")
	}

	r := &reader{buf: b, pos: 0}

	hdr, err := parseHeader(r)
	if err != nil {
		return nil, err
	}

	subFiles, err := parseSubFileDescriptors(r, hdr)
	if err != nil {
		return nil, err
	}

	file := &nvbk.NVBKFile{
		Header:   hdr,
		SubFiles: subFiles,
	}

	// Compute derived header values.
	populateSummary(file)

	Log.Debugf("parsed %s: buildTime=%s subFiles=%d total=%d valid=%d verify=%v",
		path, hdr.BuildTime, len(subFiles), hdr.Total, hdr.Valid, hdr.Verify)

	return file, nil
}

type reader struct {
	buf []byte
	pos int
}

func (r *reader) ReadByte() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) ReadBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.buf) {
		return nil, io.EOF
	}
	out := make([]byte, n)
	copy(out, r.buf[r.pos:r.pos+n])
	r.pos += n
	return out, nil
}

func (r *reader) Skip(n int) error {
	if r.pos+n > len(r.buf) {
		return io.EOF
	}
	r.pos += n
	return nil
}

func (r *reader) PeekByte() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	return r.buf[r.pos], nil
}

func parseHeader(r *reader) (nvbk.NVBKHeader, error) {
	var hdr nvbk.NVBKHeader

	magic, err := r.ReadBytes(8)
	if err != nil {
		return hdr, fmt.Errorf("unable to read magic: %w", err)
	}
	if string(magic[:7]) != "OEMNVBK" {
		return hdr, fmt.Errorf("invalid magic: %q", string(magic[:7]))
	}
	hdr.Magic = string(magic[:7])

	version, err := r.ReadBytes(4)
	if err != nil {
		return hdr, fmt.Errorf("unable to read version: %w", err)
	}
	copy(hdr.Version[:], version)

	subFileCount, err := r.ReadByte()
	if err != nil {
		return hdr, fmt.Errorf("unable to read sub-file count: %w", err)
	}
	hdr.SubFileCount = int(subFileCount)

	tblOffBytes, err := r.ReadBytes(4)
	if err != nil {
		return hdr, fmt.Errorf("unable to read table offset: %w", err)
	}
	hdr.TableOffset = binary.LittleEndian.Uint32(tblOffBytes)

	// Skip to offset 0x12 where the build date is stored as YY/MM/DD bytes.
	// The byte at 0x11 is a header flag (often 0x01).
	if err := r.Skip(0x12 - r.pos); err != nil {
		return hdr, fmt.Errorf("unable to skip to build time: %w", err)
	}

	buildTime, err := r.ReadBytes(3)
	if err != nil {
		return hdr, fmt.Errorf("unable to read build time: %w", err)
	}
	hdr.BuildTime = fmt.Sprintf("%02d%02d%02d", buildTime[0], buildTime[1], buildTime[2])

	return hdr, nil
}

func parseSubFileDescriptors(r *reader, hdr nvbk.NVBKHeader) ([]nvbk.NVBKSubFile, error) {
	if int(hdr.TableOffset)+hdr.SubFileCount*subFileDescSize > len(r.buf) {
		return nil, errors.New("sub-file table exceeds file bounds")
	}

	var subFiles []nvbk.NVBKSubFile
	for i := 0; i < hdr.SubFileCount; i++ {
		off := int(hdr.TableOffset) + i*subFileDescSize
		desc := r.buf[off : off+subFileDescSize]

		startSector := binary.LittleEndian.Uint16(desc[4:6])
		numSectors := binary.LittleEndian.Uint16(desc[6:8])
		rfID := desc[0x28]

		start := int(startSector) * 512
		length := int(numSectors) * 512
		if start+length > len(r.buf) {
			Log.Warnf("sub-file %d exceeds file bounds, truncating", i)
			length = max(len(r.buf)-start, 0)
		}

		raw := r.buf[start : start+length]
		sf := nvbk.NVBKSubFile{
			Index:       i,
			StartSector: startSector,
			NumSectors:  numSectors,
			RFID:        rfID,
			CountHint:   desc[0],
			Raw:         raw,
		}

		sf.Entries = parseEntries(raw)
		sf.ItemCount = len(sf.Entries)

		sf.Items = parseNVItems(raw)

		// Some sub-files are compressed blobs of NV items.
		sf.ItemCount = max(sf.ItemCount, compressedItemCount(raw))
		sf.ItemCount = max(sf.ItemCount, int(sf.CountHint))

		subFiles = append(subFiles, sf)
	}

	return subFiles, nil
}

// parseEntries parses the simple path-based entry format used by uncompressed
// sub-files. The layout is:
//
//	[4:total] [4:tag] [2:unknown] [2:pathLenWithNull] [path] [2:sep=0x0002] [2:dataLen] [data]
func parseEntries(raw []byte) []nvbk.NVBKEntry {
	var entries []nvbk.NVBKEntry
	off := 0
	for off+12 <= len(raw) {
		total := int(binary.LittleEndian.Uint32(raw[off : off+4]))
		if total == 0 || off+total > len(raw) || total < 12 {
			break
		}

		tag := binary.LittleEndian.Uint32(raw[off+4 : off+8])
		pathLen := int(binary.LittleEndian.Uint16(raw[off+10 : off+12]))
		if pathLen == 0 || off+12+pathLen > off+total {
			break
		}

		pathBytes := raw[off+12 : off+12+pathLen]
		nameBytes, _, ok := bytes.Cut(pathBytes, []byte{0})
		if !ok {
			break
		}
		name := string(nameBytes)

		dataStart := off + 12 + pathLen + 4 // skip separator + dataLen
		if dataStart > off+total {
			break
		}
		data := raw[dataStart : off+total]

		entries = append(entries, nvbk.NVBKEntry{
			Name: name,
			Tag:  tag,
			Data: data,
		})

		off += total
	}
	return entries
}

// compressedItemCount looks for a zlib stream inside the sub-file and, when
// decompressed, returns the byte at offset 7 which appears to hold the number
// of NV items in static_nvbk compressed blobs.
func compressedItemCount(raw []byte) int {
	idx := bytes.Index(raw, []byte{0x78, 0x9c})
	if idx < 0 {
		return 0
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[idx:]))
	if err != nil {
		return 0
	}
	defer zr.Close()

	buf := make([]byte, 8)
	n, _ := io.ReadFull(zr, buf)
	if n < 8 {
		return 0
	}
	return int(buf[7])
}

// parseNVItems extracts numeric NV item IDs from sub-files that use the
// ID-directory format. It tries every zlib stream inside the sub-file (and the
// raw bytes) and returns the directory with the most IDs.
func parseNVItems(raw []byte) []nvbk.NVBKItem {
	var best []nvbk.NVBKItem

	if items := parseNVItemDirectory(raw); len(items) > len(best) {
		best = items
	}

	start := 0
	for {
		idx := bytes.Index(raw[start:], []byte{0x78, 0x9c})
		if idx < 0 {
			break
		}
		idx += start
		zr, err := zlib.NewReader(bytes.NewReader(raw[idx:]))
		if err == nil {
			out, _ := io.ReadAll(zr)
			zr.Close()
			if items := parseNVItemDirectory(out); len(items) > len(best) {
				best = items
			}
		}
		start = idx + 1
	}

	return best
}

// parseNVItemDirectory parses a single ID-directory payload.
// The header has a count at offset 7 and is followed by 24-byte groups; each
// group contains four 6-byte slots (4 zero bytes + 2-byte ID in little-endian).
func parseNVItemDirectory(data []byte) []nvbk.NVBKItem {
	if len(data) < 16 {
		return nil
	}

	if data[0] != 0 || data[1] != 0 || data[7] == 0 {
		return nil
	}

	// Directory signatures observed in static_nvbk ID tables: byte 4 is 0x34.
	if data[4] != 0x34 {
		return nil
	}

	count := int(data[7])
	if len(data) < 16+count*24 {
		return nil
	}

	// Validate that most slots have the expected zero prefix; otherwise this is
	// probably compressed container data rather than an ID directory.
	zeroPrefix := 0
	totalSlots := count * 4
	for i := range count {
		off := 16 + i*24
		for slot := range 4 {
			if binary.LittleEndian.Uint32(data[off+slot*6 : off+slot*6+4]) == 0 {
				zeroPrefix++
			}
		}
	}
	if zeroPrefix*2 < totalSlots {
		return nil
	}

	var items []nvbk.NVBKItem
	for i := range count {
		off := 16 + i*24
		for slot := range 4 {
			idOff := off + slot*6 + 4
			id := binary.LittleEndian.Uint16(data[idOff : idOff+2])
			if id != 0 {
				items = append(items, nvbk.NVBKItem{ID: id})
			}
		}
	}
	return items
}

// FindNVItem searches all sub-files (including zlib-compressed streams) for a
// numeric NV item record with the given ID. It returns the sub-file index and
// the record's data payload, or -1/nil if not found.
func FindNVItem(f *nvbk.NVBKFile, id uint16) (int, []byte) {
	idBytes := [2]byte{byte(id), byte(id >> 8)}

	for _, sf := range f.SubFiles {
		if data := findNVItemInBlob(sf.Raw, idBytes); data != nil {
			return sf.Index, data
		}

		start := 0
		for {
			idx := bytes.Index(sf.Raw[start:], []byte{0x78, 0x9c})
			if idx < 0 {
				break
			}
			idx += start
			zr, err := zlib.NewReader(bytes.NewReader(sf.Raw[idx:]))
			if err == nil {
				out, _ := io.ReadAll(zr)
				zr.Close()
				if data := findNVItemInBlob(out, idBytes); data != nil {
					return sf.Index, data
				}
			}
			start = idx + 1
		}
	}

	return -1, nil
}

func findNVItemInBlob(blob []byte, idBytes [2]byte) []byte {
	for i := range len(blob) - 4 {
		if blob[i] != idBytes[0] || blob[i+1] != idBytes[1] {
			continue
		}
		total := int(binary.LittleEndian.Uint16(blob[i+2 : i+4]))
		if total < 4 || total > 0x1000 || i+total > len(blob) {
			continue
		}
		return blob[i+4 : i+total]
	}
	return nil
}

func populateSummary(f *nvbk.NVBKFile) {
	maxCount := 0
	for i := range f.SubFiles {
		if f.SubFiles[i].ItemCount > maxCount {
			maxCount = f.SubFiles[i].ItemCount
		}
	}

	f.Header.Total = maxCount
	f.Header.Valid = maxCount
	f.Header.Verify = maxCount > 0 && len(f.SubFiles) > 0
}

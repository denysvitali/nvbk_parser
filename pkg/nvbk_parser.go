package nvbk_parser

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
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
	if hdr.TableOffset != 0x1c && int(hdr.TableOffset) > headerSize {
		return hdr, fmt.Errorf("unexpected table offset: 0x%x", hdr.TableOffset)
	}

	headerFlag, err := r.ReadByte()
	if err != nil {
		return hdr, fmt.Errorf("unable to read header flag: %w", err)
	}
	hdr.HeaderFlag = headerFlag

	buildTime, err := r.ReadBytes(3)
	if err != nil {
		return hdr, fmt.Errorf("unable to read build time: %w", err)
	}
	hdr.BuildTime = fmt.Sprintf("%02d%02d%02d", buildTime[0], buildTime[1], buildTime[2])

	reserved, err := r.ReadBytes(1)
	if err != nil {
		return hdr, fmt.Errorf("unable to read reserved byte: %w", err)
	}
	hdr.ReservedAfterBuild[0] = reserved[0]

	sig, err := r.ReadBytes(6)
	if err != nil {
		return hdr, fmt.Errorf("unable to read signature/reserved region: %w", err)
	}
	copy(hdr.SignatureOrReserved[:], sig)

	remainder, err := r.ReadBytes(headerSize - r.pos)
	if err != nil {
		return hdr, fmt.Errorf("unable to read header remainder: %w", err)
	}
	hdr.HeaderRemainder = make([]byte, len(remainder))
	copy(hdr.HeaderRemainder, remainder)

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
			PayloadHash: append([]byte(nil), desc[8:40]...),
			Raw:         raw,
		}

		expectedLength := int(numSectors) * 512
		actualLength := length
		if actualLength < expectedLength {
			Log.Warnf("sub-file %d is truncated: expected %d bytes, got %d; hash verification skipped", i, expectedLength, actualLength)
		} else {
			hash := sha256.Sum256(raw)
			sf.Verified = bytes.Equal(hash[:], sf.PayloadHash)
		}

		sf.Entries = parseEntries(raw)
		sf.Items = parseNVItems(raw)

		// ItemCount is derived from the directory/count hints rather than the
		// path-based entry list so that the header summary stays stable when the
		// parser discovers additional metadata records.
		sf.ItemCount = compressedItemCount(raw)
		sf.ItemCount = max(sf.ItemCount, len(sf.Items))
		sf.ItemCount = max(sf.ItemCount, int(sf.CountHint))

		subFiles = append(subFiles, sf)
	}

	return subFiles, nil
}

// parseEntries parses the simple path-based entry format used by uncompressed
// sub-files. The layout is:
//
//	[4:total] [4:tag] [2:typeMarker=0x0001] [2:pathLenWithNull] [path] [2:sep=0x0002] [2:dataLen] [data]
//
// Metadata records (typeMarker != 0x0001) are skipped. The first entry is found
// by scanning; subsequent entries are parsed contiguously until the data ends or
// a record does not match the expected structure.
func parseEntries(raw []byte) []nvbk.NVBKEntry {
	if len(raw) < 12 {
		return nil
	}

	var entries []nvbk.NVBKEntry
	off := 0
	scanning := true

	for off+12 <= len(raw) {
		// Stop cleanly on sector-boundary zero padding.
		if off+12 <= len(raw) && bytes.Equal(raw[off:off+12], make([]byte, 12)) {
			break
		}

		typeMarker := binary.LittleEndian.Uint16(raw[off+8 : off+10])
		if scanning {
			if typeMarker != 0x0001 {
				off++
				continue
			}
			// Path entries have the tag low-byte set to 0x02.
			tag := binary.LittleEndian.Uint32(raw[off+4 : off+8])
			if byte(tag) != 0x02 {
				off++
				continue
			}
			scanning = false
		} else {
			if typeMarker != 0x0001 {
				break
			}
		}

		total := int(binary.LittleEndian.Uint32(raw[off : off+4]))
		if total == 0 || off+total > len(raw) || total < 12 {
			if scanning {
				off++
				continue
			}
			break
		}

		tag := binary.LittleEndian.Uint32(raw[off+4 : off+8])
		if byte(tag) != 0x02 {
			if scanning {
				off++
				continue
			}
			break
		}

		pathLen := int(binary.LittleEndian.Uint16(raw[off+10 : off+12]))
		if pathLen == 0 || off+12+pathLen > off+total {
			if scanning {
				off++
				continue
			}
			break
		}

		pathBytes := raw[off+12 : off+12+pathLen]
		nameBytes, _, ok := bytes.Cut(pathBytes, []byte{0})
		if !ok {
			if scanning {
				off++
				continue
			}
			break
		}
		name := string(nameBytes)

		sepOff := off + 12 + pathLen
		if sepOff+2 > off+total {
			if scanning {
				off++
				continue
			}
			break
		}
		separator := binary.LittleEndian.Uint16(raw[sepOff : sepOff+2])
		if separator != 0x0002 {
			if scanning {
				off++
				continue
			}
			break
		}

		dataStart := sepOff + 4 // skip separator + dataLen
		if dataStart > off+total {
			if scanning {
				off++
				continue
			}
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

// parseNVItems extracts numeric NV items from compressed sub-files. It searches
// decompressed zlib streams, parses the ID-directory header, and recovers each
// item's payload from ID+total+payload records in the decompressed streams.
func parseNVItems(raw []byte) []nvbk.NVBKItem {
	var best []nvbk.NVBKItem
	var blobs [][]byte

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
			blobs = append(blobs, out)
			if items := parseNVItemDirectory(out); len(items) > 0 && len(items) > len(best) {
				best = items
			}
		}
		start = idx + 1
	}

	if len(best) == 0 {
		return nil
	}

	for i := range best {
		idBytes := [2]byte{byte(best[i].ID), byte(best[i].ID >> 8)}
		for _, blob := range blobs {
			if data := findNVItemInBlob(blob, idBytes); data != nil {
				best[i].Data = data
				break
			}
		}
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
			if binary.LittleEndian.Uint32(data[off+slot*6:off+slot*6+4]) == 0 {
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
	for i := 0; i <= len(blob)-4; i++ {
		if blob[i] != idBytes[0] || blob[i+1] != idBytes[1] {
			continue
		}
		total := int(binary.LittleEndian.Uint16(blob[i+2 : i+4]))
		if total < 4 || total > 0x1000 || i+total > len(blob) {
			continue
		}
		// Chain-validate: the next record must also be a valid ID+total structure.
		if i+total < len(blob) && !isValidNVItemRecord(blob, i+total) {
			continue
		}
		return blob[i+4 : i+total]
	}
	return nil
}

// isValidNVItemRecord reports whether a candidate record at offset off has a
// valid ID+total structure. A zero ID with zero total is accepted as the
// end-of-records marker (padding).
func isValidNVItemRecord(blob []byte, off int) bool {
	if off+4 > len(blob) {
		return false
	}
	id := binary.LittleEndian.Uint16(blob[off : off+2])
	total := int(binary.LittleEndian.Uint16(blob[off+2 : off+4]))
	if id == 0 && total == 0 {
		return true
	}
	return id != 0 && total >= 4 && total <= 0x1000 && off+total <= len(blob)
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

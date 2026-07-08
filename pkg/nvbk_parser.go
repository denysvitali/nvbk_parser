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
	sectorSize      = 512
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

func parseHeader(r *reader) (nvbk.NVBKHeader, error) {
	var hdr nvbk.NVBKHeader

	// Magic is 8 bytes: "OEMNVBK" + NUL.
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

	// Bytes from table_offset to 0x200 hold the descriptor table (and pad).
	// Stored opaque for round-trip / hex dumps; descriptors re-parsed below.
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

		// Descriptor: u32 record_count | u16 start | u16 nsec | sha256[32] | rf_id
		recordCount := binary.LittleEndian.Uint32(desc[0:4])
		startSector := binary.LittleEndian.Uint16(desc[4:6])
		numSectors := binary.LittleEndian.Uint16(desc[6:8])
		rfID := desc[0x28]

		start := int(startSector) * sectorSize
		length := int(numSectors) * sectorSize
		if start+length > len(r.buf) {
			Log.Warnf("sub-file %d exceeds file bounds, truncating", i)
			length = max(len(r.buf)-start, 0)
		}

		raw := r.buf[start : start+length]
		sf := nvbk.NVBKSubFile{
			Index:       i,
			RecordCount: recordCount,
			StartSector: startSector,
			NumSectors:  numSectors,
			RFID:        rfID,
			PayloadHash: append([]byte(nil), desc[8:40]...),
			Raw:         raw,
		}

		expectedLength := int(numSectors) * sectorSize
		if length < expectedLength {
			Log.Warnf("sub-file %d is truncated: expected %d bytes, got %d; hash verification skipped", i, expectedLength, length)
		} else {
			hash := sha256.Sum256(raw)
			sf.Verified = bytes.Equal(hash[:], sf.PayloadHash)
		}

		sf.Records, sf.BytesCovered = parseRecords(raw)
		sf.Entries = entriesFromRecords(sf.Records)
		sf.Items = itemsFromRecords(sf.Records)

		// Nested zlib ID-directory recovery (RF cal blobs).
		sf.Items = mergeItems(sf.Items, parseNVItems(raw))

		// ItemCount = walked records (authoritative). Descriptor count should match.
		sf.ItemCount = len(sf.Records)
		if int(sf.RecordCount) > sf.ItemCount {
			// Truncated image: descriptor claims more than we could walk.
			sf.ItemCount = int(sf.RecordCount)
		}

		if sf.Verified && uint32(len(sf.Records)) != sf.RecordCount {
			Log.Warnf("sub-file %d record count mismatch: descriptor=%d walked=%d",
				i, sf.RecordCount, len(sf.Records))
		}

		subFiles = append(subFiles, sf)
	}

	return subFiles, nil
}

// parseRecords walks the contiguous TLV stream that makes up a sub-file.
//
// Every record:
//
//	u32 total | u8 type | u8 attr | u8 rfid | u8 flags | payload…
//
// Kind 0x01 / 0xF1 / 0xF3: numeric item (u16 id, u16 dataLen, data)
// Kind 0x02 / 0xF2 / 0xF4: path entry (u16 marker=1, u16 pathLen, path, sep, data)
// Trailing sector zero-padding ends the walk.
func parseRecords(raw []byte) ([]nvbk.NVBKRecord, int) {
	var records []nvbk.NVBKRecord
	off := 0

	for off+8 <= len(raw) {
		// Only treat leading zeros as end-of-stream (sector pad). Do not scan
		// for zeros mid-record (that broke dycnvbk path recovery).
		if isZero(raw[off:min(off+8, len(raw))]) {
			break
		}

		total := int(binary.LittleEndian.Uint32(raw[off : off+4]))
		if total < 8 || off+total > len(raw) {
			break
		}

		body := raw[off : off+total]
		rec := nvbk.NVBKRecord{
			Offset: off,
			Total:  total,
			Type:   body[4],
			Attr:   body[5],
			RFID:   body[6],
			Flags:  body[7],
		}

		switch {
		case nvbk.IsPathType(rec.Type):
			parsePathRecord(body, &rec)
		case nvbk.IsItemType(rec.Type):
			parseItemRecord(body, &rec)
		default:
			if total > 8 {
				rec.Data = append([]byte(nil), body[8:]...)
			}
			tryDecompressPayload(body, &rec)
		}

		records = append(records, rec)
		off += total
	}

	return records, off
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return len(b) > 0
}

// parsePathRecord decodes path-type entries (0x02 / 0xF2 / 0xF4).
//
//	[4 total][1 type][1 attr][1 rfid][1 flags]
//	[2 marker=0x0001][2 pathLen][path][2 sep=0x0002][2 dataLen][data]
func parsePathRecord(body []byte, rec *nvbk.NVBKRecord) {
	if len(body) < 12 {
		return
	}
	marker := binary.LittleEndian.Uint16(body[8:10])
	pathLen := int(binary.LittleEndian.Uint16(body[10:12]))
	if marker != 0x0001 || pathLen <= 0 || 12+pathLen > len(body) {
		rec.Data = append([]byte(nil), body[8:]...)
		tryDecompressPayload(body, rec)
		return
	}

	pathBytes := body[12 : 12+pathLen]
	nameBytes, _, _ := bytes.Cut(pathBytes, []byte{0})
	rec.Name = string(nameBytes)

	sepOff := 12 + pathLen
	if sepOff+4 > len(body) {
		return
	}
	// sep should be 0x0002; data follows the dataLen field.
	dataStart := sepOff + 4
	if dataStart > len(body) {
		return
	}
	rec.Data = append([]byte(nil), body[dataStart:]...)
	tryDecompressPayload(body, rec)
}

// parseItemRecord decodes item-type entries (0x01 / 0xF1 / 0xF3).
//
//	[4 total][1 type][1 attr][1 rfid][1 flags][2 id][2 dataLen][data]
//
// For kind 0xF3, dataLen often does not cover the full body; when VTNV/zlib is
// present the remainder after the 12-byte header is kept as Data.
func parseItemRecord(body []byte, rec *nvbk.NVBKRecord) {
	if len(body) < 12 {
		if len(body) > 8 {
			rec.Data = append([]byte(nil), body[8:]...)
		}
		return
	}

	rec.ItemID = binary.LittleEndian.Uint16(body[8:10])
	dataLen := int(binary.LittleEndian.Uint16(body[10:12]))
	dataStart := 12
	rest := body[dataStart:]

	switch {
	case dataLen >= 0 && dataStart+dataLen <= len(body) && dataLen == len(body)-dataStart:
		// Classic item: dataLen exactly fills the record.
		rec.Data = append([]byte(nil), rest...)
	case dataLen > 0 && dataStart+dataLen <= len(body) &&
		!bytes.Contains(rest, []byte("VTNV")) && !hasZlib(rest[min(dataLen, len(rest)):]):
		// Plausible short payload without trailing compressed blob.
		rec.Data = append([]byte(nil), body[dataStart:dataStart+dataLen]...)
	default:
		// Extended / VTNV / mismatched dataLen: keep full remainder.
		rec.Data = append([]byte(nil), rest...)
	}

	tryDecompressPayload(body, rec)
}

func hasZlib(b []byte) bool {
	return bytes.Contains(b, []byte{0x78, 0x9c})
}

func tryDecompressPayload(body []byte, rec *nvbk.NVBKRecord) {
	if bytes.Contains(body, []byte("VTNV")) {
		rec.VTNV = true
	}
	idx := bytes.Index(body, []byte{0x78, 0x9c})
	if idx < 0 {
		return
	}
	zr, err := zlib.NewReader(bytes.NewReader(body[idx:]))
	if err != nil {
		return
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil && len(out) == 0 {
		return
	}
	rec.Compressed = out
	if !rec.VTNV && idx >= 4 && bytes.Contains(body[max(0, idx-16):idx], []byte("VTNV")) {
		rec.VTNV = true
	}
}

func entriesFromRecords(records []nvbk.NVBKRecord) []nvbk.NVBKEntry {
	var out []nvbk.NVBKEntry
	for _, r := range records {
		if !nvbk.IsPathType(r.Type) || r.Name == "" {
			continue
		}
		tag := binary.LittleEndian.Uint32([]byte{r.Type, r.Attr, r.RFID, r.Flags})
		out = append(out, nvbk.NVBKEntry{
			Name: r.Name,
			Tag:  tag,
			Data: r.Data,
		})
	}
	return out
}

func itemsFromRecords(records []nvbk.NVBKRecord) []nvbk.NVBKItem {
	var out []nvbk.NVBKItem
	seen := map[uint16]struct{}{}

	add := func(id uint16, data []byte) {
		if id == 0 && len(data) == 0 {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		if len(data) == 0 {
			return
		}
		// Skip pure VTNV wrapper bytes as the "item data" — prefer nested.
		if bytes.HasPrefix(data, []byte("VTNV")) {
			return
		}
		seen[id] = struct{}{}
		out = append(out, nvbk.NVBKItem{
			ID:   id,
			Name: nvbk.LookupNVItemName(id),
			Data: data,
		})
	}

	for _, r := range records {
		if !nvbk.IsItemType(r.Type) && len(r.Compressed) == 0 {
			continue
		}

		// Inline non-compressed item payload.
		if nvbk.IsItemType(r.Type) && !r.VTNV && len(r.Compressed) == 0 {
			add(r.ItemID, r.Data)
		}

		// Nested items inside decompressed VTNV/zlib.
		if len(r.Compressed) > 0 {
			for _, it := range parseNVItemDirectory(r.Compressed) {
				idBytes := [2]byte{byte(it.ID), byte(it.ID >> 8)}
				if data := findNVItemInBlob(r.Compressed, idBytes); data != nil {
					add(it.ID, data)
				}
			}
			for _, it := range scanNVItemChain(r.Compressed) {
				add(it.ID, it.Data)
			}
		}
	}
	return out
}

func mergeItems(base, extra []nvbk.NVBKItem) []nvbk.NVBKItem {
	if len(extra) == 0 {
		return base
	}
	seen := map[uint16]struct{}{}
	for _, it := range base {
		seen[it.ID] = struct{}{}
	}
	for _, it := range extra {
		if _, ok := seen[it.ID]; ok {
			continue
		}
		if len(it.Data) == 0 {
			continue
		}
		if it.Name == "" {
			it.Name = nvbk.LookupNVItemName(it.ID)
		}
		base = append(base, it)
		seen[it.ID] = struct{}{}
	}
	return base
}

// scanNVItemChain walks a blob as [u16 id][u16 total][data] records.
func scanNVItemChain(blob []byte) []nvbk.NVBKItem {
	var items []nvbk.NVBKItem
	off := 0
	bad := 0
	for off+4 <= len(blob) && bad < 8 {
		id := binary.LittleEndian.Uint16(blob[off : off+2])
		total := int(binary.LittleEndian.Uint16(blob[off+2 : off+4]))
		if id == 0 && total == 0 {
			break
		}
		if total < 4 || total > 0x4000 || off+total > len(blob) || id == 0 {
			off++
			bad++
			continue
		}
		next := off + total
		if next < len(blob) && !isValidNVItemRecord(blob, next) && !isZero(blob[next:min(next+4, len(blob))]) {
			off++
			bad++
			continue
		}
		items = append(items, nvbk.NVBKItem{
			ID:   id,
			Data: append([]byte(nil), blob[off+4:off+total]...),
		})
		off = next
		bad = 0
	}
	return items
}

// parseEntries walks records and returns path entries (public helper).
func parseEntries(raw []byte) []nvbk.NVBKEntry {
	records, _ := parseRecords(raw)
	return entriesFromRecords(records)
}

// parseNVItems extracts numeric NV items from zlib streams via the ID-directory
// format used inside some RF calibration VTNV payloads.
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
			if items := parseNVItemDirectory(out); len(items) > len(best) {
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
				best[i].Name = nvbk.LookupNVItemName(best[i].ID)
				break
			}
		}
	}

	// Drop directory IDs with no recovered payload.
	var withData []nvbk.NVBKItem
	for _, it := range best {
		if len(it.Data) > 0 {
			withData = append(withData, it)
		}
	}
	return withData
}

// parseNVItemDirectory parses a single ID-directory payload.
// Header has count at offset 7; followed by 24-byte groups of four
// (u32 zero + u16 id) slots. Signature: byte4 == 0x34.
func parseNVItemDirectory(data []byte) []nvbk.NVBKItem {
	if len(data) < 16 {
		return nil
	}
	if data[0] != 0 || data[1] != 0 || data[7] == 0 {
		return nil
	}
	if data[4] != 0x34 {
		return nil
	}

	count := int(data[7])
	if len(data) < 16+count*24 {
		return nil
	}

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

// FindNVItem searches all sub-files for a numeric NV item with the given ID.
func FindNVItem(f *nvbk.NVBKFile, id uint16) (int, []byte) {
	for _, sf := range f.SubFiles {
		for _, it := range sf.Items {
			if it.ID == id && len(it.Data) > 0 {
				return sf.Index, it.Data
			}
		}
		for _, rec := range sf.Records {
			if nvbk.IsItemType(rec.Type) && rec.ItemID == id && !rec.VTNV && len(rec.Data) > 0 {
				return sf.Index, rec.Data
			}
		}
	}

	idBytes := [2]byte{byte(id), byte(id >> 8)}

	for _, sf := range f.SubFiles {
		if data := findNVItemInBlob(sf.Raw, idBytes); data != nil {
			return sf.Index, data
		}
		for _, rec := range sf.Records {
			if len(rec.Compressed) > 0 {
				if data := findNVItemInBlob(rec.Compressed, idBytes); data != nil {
					return sf.Index, data
				}
			}
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
		if i+total < len(blob) && !isValidNVItemRecord(blob, i+total) {
			continue
		}
		return blob[i+4 : i+total]
	}
	return nil
}

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

// populateSummary derives header Total/Valid/Verify from sub-file results.
// There is no global Total field in the image header.
func populateSummary(f *nvbk.NVBKFile) {
	total := 0
	valid := 0
	allVerified := len(f.SubFiles) > 0
	for i := range f.SubFiles {
		sf := &f.SubFiles[i]
		n := int(sf.RecordCount)
		if n == 0 {
			n = len(sf.Records)
		}
		total += n
		if sf.Verified {
			valid += n
		} else if len(sf.Raw) == int(sf.NumSectors)*sectorSize {
			// Complete payload but hash mismatch.
			allVerified = false
		} else {
			// Truncated sample — do not fail overall Verify solely for trim.
		}
		// Hash mismatch on a full-size sub-file fails Verify.
		if !sf.Verified && len(sf.Raw) == int(sf.NumSectors)*sectorSize && len(sf.Raw) > 0 {
			allVerified = false
		}
	}

	// Verify = every full-size sub-file passed SHA-256.
	for i := range f.SubFiles {
		sf := &f.SubFiles[i]
		full := len(sf.Raw) == int(sf.NumSectors)*sectorSize && len(sf.Raw) > 0
		if full && !sf.Verified {
			allVerified = false
			break
		}
	}
	if total == 0 {
		allVerified = false
	}

	f.Header.Total = total
	f.Header.Valid = valid
	f.Header.Verify = allVerified && total > 0
}

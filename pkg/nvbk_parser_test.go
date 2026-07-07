package nvbk_parser

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseStaNVBKFileOP8PROO2OS1056(t *testing.T) {
	parsedFile, err := ReadFile("../resources/op8pro_o2os_10.5.6.in11ba_stanvbk_trimmed.img")
	assert.Nil(t, err)
	assert.Equal(t, 86, parsedFile.Header.Total)
	assert.Equal(t, 86, parsedFile.Header.Valid)
	assert.Equal(t, true, parsedFile.Header.Verify)
	assert.Equal(t, "200426", parsedFile.Header.BuildTime)
}

func TestParseDycNVBKFileOP8PROO2OS1056(t *testing.T) {
	parsedFile, err := ReadFile("../resources/op8pro_o2os_10.5.6.in11ba_dycnvbk_trimmed.img")
	assert.Nil(t, err)
	assert.Equal(t, 33, parsedFile.Header.Total)
	assert.Equal(t, 33, parsedFile.Header.Valid)
	assert.Equal(t, true, parsedFile.Header.Verify)
	assert.Equal(t, "200321", parsedFile.Header.BuildTime)
}

func TestParseStaNVBKFileOP7T(t *testing.T) {
	parsedFile, err := ReadFile("../resources/op7t_oem_stanvbk.img")
	assert.Nil(t, err)
	assert.Equal(t, 45, parsedFile.Header.Total)
	assert.Equal(t, 45, parsedFile.Header.Valid)
	assert.Equal(t, true, parsedFile.Header.Verify)
	assert.Equal(t, "190925", parsedFile.Header.BuildTime)
}

func TestParseStaNVBKFileOPLUS(t *testing.T) {
	parsedFile, err := ReadFile("../resources/oplusstanvbk.img")
	assert.Nil(t, err)
	assert.Equal(t, 82, parsedFile.Header.Total)
	assert.Equal(t, 82, parsedFile.Header.Valid)
	assert.Equal(t, true, parsedFile.Header.Verify)
	assert.Equal(t, "241224", parsedFile.Header.BuildTime)
}

func TestParseStaNVBKFileOEM(t *testing.T) {
	parsedFile, err := ReadFile("../resources/oem_stanvbk-2019-10-23")
	assert.Nil(t, err)
	assert.Equal(t, 255, parsedFile.Header.Total)
	assert.Equal(t, 255, parsedFile.Header.Valid)
	assert.Equal(t, true, parsedFile.Header.Verify)
	assert.Equal(t, "191008", parsedFile.Header.BuildTime)
}

func TestHeaderFields(t *testing.T) {
	cases := []struct {
		path      string
		flag      byte
		tableOff  uint32
		buildTime string
		subFiles  int
	}{
		{"../resources/oem_stanvbk-2019-10-23", 0x00, 0x1c, "191008", 7},
		{"../resources/op7t_oem_stanvbk.img", 0x00, 0x1c, "190925", 6},
		{"../resources/op8pro_o2os_10.5.6.in11ba_dycnvbk_trimmed.img", 0x01, 0x1c, "200321", 1},
		{"../resources/op8pro_o2os_10.5.6.in11ba_stanvbk_trimmed.img", 0x01, 0x1c, "200426", 10},
		{"../resources/oplusstanvbk.img", 0x02, 0x1c, "241224", 12},
	}
	for _, tc := range cases {
		f, err := ReadFile(tc.path)
		assert.Nil(t, err, tc.path)
		assert.Equal(t, tc.flag, f.Header.HeaderFlag, tc.path)
		assert.Equal(t, tc.tableOff, f.Header.TableOffset, tc.path)
		assert.Equal(t, tc.buildTime, f.Header.BuildTime, tc.path)
		assert.Equal(t, tc.subFiles, f.Header.SubFileCount, tc.path)
		assert.Equal(t, [1]byte{0}, f.Header.ReservedAfterBuild, tc.path)
		if tc.path == "../resources/oplusstanvbk.img" {
			assert.Equal(t, [6]byte{'5', 'a', '2', 'a', '4', '1'}, f.Header.SignatureOrReserved, tc.path)
		} else {
			assert.Equal(t, [6]byte{0, 0, 0, 0, 0, 0}, f.Header.SignatureOrReserved, tc.path)
		}
	}
}

func TestDescriptorVerification(t *testing.T) {
	// Full samples should have all payload hashes matching.
	full := []string{
		"../resources/oem_stanvbk-2019-10-23",
		"../resources/op7t_oem_stanvbk.img",
		"../resources/oplusstanvbk.img",
	}
	for _, p := range full {
		f, err := ReadFile(p)
		assert.Nil(t, err, p)
		for _, sf := range f.SubFiles {
			assert.True(t, sf.Verified, "sub-file %d of %s should be verified", sf.Index, p)
			assert.Len(t, sf.PayloadHash, 32, "sub-file %d of %s should have a SHA-256 hash", sf.Index, p)
		}
	}

	// Trimmed samples have at least one descriptor that cannot be fully verified.
	trimmed := []string{
		"../resources/op8pro_o2os_10.5.6.in11ba_dycnvbk_trimmed.img",
		"../resources/op8pro_o2os_10.5.6.in11ba_stanvbk_trimmed.img",
	}
	for _, p := range trimmed {
		f, err := ReadFile(p)
		assert.Nil(t, err, p)
		unverified := 0
		for _, sf := range f.SubFiles {
			if !sf.Verified {
				unverified++
			}
		}
		assert.Greater(t, unverified, 0, "trimmed sample %s should have unverified sub-files", p)
	}
}

func TestFindNVItemReturnsData(t *testing.T) {
	f, err := ReadFile("../resources/op7t_oem_stanvbk.img")
	assert.Nil(t, err)
	assert.NotEmpty(t, f.SubFiles)

	var target uint16
	for _, sf := range f.SubFiles {
		if len(sf.Items) > 0 {
			target = sf.Items[0].ID
			break
		}
	}
	assert.NotZero(t, target, "expected at least one numeric NV item")

	idx, data := FindNVItem(f, target)
	assert.GreaterOrEqual(t, idx, 0)
	assert.NotNil(t, data)
	assert.NotEmpty(t, data)
}

func TestReadFileMissing(t *testing.T) {
	_, err := ReadFile("../resources/does-not-exist.img")
	assert.Error(t, err)
}

func TestReadFileTooSmall(t *testing.T) {
	tmp, err := os.CreateTemp("", "nvbk-small-*.img")
	assert.Nil(t, err)
	defer os.Remove(tmp.Name())

	_, err = tmp.Write([]byte("OEMNVBK"))
	assert.Nil(t, err)
	assert.Nil(t, tmp.Close())

	_, err = ReadFile(tmp.Name())
	assert.Error(t, err)
}

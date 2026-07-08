package nvbk_parser

import (
	"os"
	"testing"

	"github.com/denysvitali/nvbk_parser/pkg/nvbk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseStaNVBKFileOP8PROO2OS1056(t *testing.T) {
	// 10 sub-files; last truncated. Total = sum of descriptor record counts.
	f, err := ReadFile("../resources/op8pro_o2os_10.5.6.in11ba_stanvbk_trimmed.img")
	require.NoError(t, err)
	assert.Equal(t, 552, f.Header.Total)
	assert.Equal(t, "200426", f.Header.BuildTime)
	assert.Equal(t, 10, f.Header.SubFileCount)
}

func TestParseDycNVBKFileOP8PROO2OS1056(t *testing.T) {
	f, err := ReadFile("../resources/op8pro_o2os_10.5.6.in11ba_dycnvbk_trimmed.img")
	require.NoError(t, err)
	assert.Equal(t, 33, f.Header.Total)
	assert.Equal(t, "200321", f.Header.BuildTime)
	assert.Len(t, f.SubFiles, 1)
	assert.Equal(t, uint32(33), f.SubFiles[0].RecordCount)
	assert.Len(t, f.SubFiles[0].Records, 33)
}

func TestParseStaNVBKFileOP7T(t *testing.T) {
	f, err := ReadFile("../resources/op7t_oem_stanvbk.img")
	require.NoError(t, err)
	// 45+44+44+45+45+44 = 267
	assert.Equal(t, 267, f.Header.Total)
	assert.Equal(t, 267, f.Header.Valid)
	assert.True(t, f.Header.Verify)
	assert.Equal(t, "190925", f.Header.BuildTime)
}

func TestParseStaNVBKFileOPLUS(t *testing.T) {
	f, err := ReadFile("../resources/oplusstanvbk.img")
	require.NoError(t, err)
	// 82+30+30+39+45+40+39+45+40+39+44+45 = 518
	assert.Equal(t, 518, f.Header.Total)
	assert.Equal(t, 518, f.Header.Valid)
	assert.True(t, f.Header.Verify)
	assert.Equal(t, "241224", f.Header.BuildTime)
}

func TestParseStaNVBKFileOEM(t *testing.T) {
	f, err := ReadFile("../resources/oem_stanvbk-2019-10-23")
	require.NoError(t, err)
	// 75+1197+1197+1196+665+1051+1177 = 6558
	assert.Equal(t, 6558, f.Header.Total)
	assert.Equal(t, 6558, f.Header.Valid)
	assert.True(t, f.Header.Verify)
	assert.Equal(t, "191008", f.Header.BuildTime)
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
		require.NoError(t, err, tc.path)
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
	full := []string{
		"../resources/oem_stanvbk-2019-10-23",
		"../resources/op7t_oem_stanvbk.img",
		"../resources/oplusstanvbk.img",
	}
	for _, p := range full {
		f, err := ReadFile(p)
		require.NoError(t, err, p)
		for _, sf := range f.SubFiles {
			assert.True(t, sf.Verified, "sub-file %d of %s", sf.Index, p)
			assert.Len(t, sf.PayloadHash, 32)
			assert.Equal(t, uint32(len(sf.Records)), sf.RecordCount,
				"sub-file %d of %s: walked records must match descriptor u32", sf.Index, p)
		}
	}

	trimmed := []string{
		"../resources/op8pro_o2os_10.5.6.in11ba_dycnvbk_trimmed.img",
		"../resources/op8pro_o2os_10.5.6.in11ba_stanvbk_trimmed.img",
	}
	for _, p := range trimmed {
		f, err := ReadFile(p)
		require.NoError(t, err, p)
		unverified := 0
		for _, sf := range f.SubFiles {
			if !sf.Verified {
				unverified++
			}
		}
		assert.Greater(t, unverified, 0, "trimmed sample %s", p)
	}
}

func TestFindNVItemReturnsData(t *testing.T) {
	f, err := ReadFile("../resources/op7t_oem_stanvbk.img")
	require.NoError(t, err)

	var target uint16
	for _, sf := range f.SubFiles {
		if len(sf.Items) > 0 {
			target = sf.Items[0].ID
			break
		}
	}
	require.NotZero(t, target)

	idx, data := FindNVItem(f, target)
	assert.GreaterOrEqual(t, idx, 0)
	assert.NotEmpty(t, data)
}

func TestReadFileMissing(t *testing.T) {
	_, err := ReadFile("../resources/does-not-exist.img")
	assert.Error(t, err)
}

func TestReadFileTooSmall(t *testing.T) {
	tmp, err := os.CreateTemp("", "nvbk-small-*.img")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())

	_, err = tmp.Write([]byte("OEMNVBK"))
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	_, err = ReadFile(tmp.Name())
	assert.Error(t, err)
}

func TestFullDecodeCoverage(t *testing.T) {
	samples := []struct {
		path            string
		minTotalRecords int
		minTotalPaths   int
		expectTotal     int
	}{
		{"../resources/oem_stanvbk-2019-10-23", 6558, 4000, 6558},
		{"../resources/op7t_oem_stanvbk.img", 267, 80, 267},
		{"../resources/oplusstanvbk.img", 518, 150, 518},
		{"../resources/op8pro_o2os_10.5.6.in11ba_dycnvbk_trimmed.img", 33, 0, 33},
		{"../resources/op8pro_o2os_10.5.6.in11ba_stanvbk_trimmed.img", 500, 20, 552},
	}

	for _, tc := range samples {
		t.Run(tc.path, func(t *testing.T) {
			f, err := ReadFile(tc.path)
			require.NoError(t, err)
			assert.Equal(t, tc.expectTotal, f.Header.Total)

			totalRecs := 0
			totalPaths := 0
			var covered, rawTotal int
			for _, sf := range f.SubFiles {
				require.NotEmpty(t, sf.Records, "sf %d empty", sf.Index)
				totalRecs += len(sf.Records)
				totalPaths += len(sf.Entries)
				covered += sf.BytesCovered
				rawTotal += len(sf.Raw)

				if sf.BytesCovered < len(sf.Raw) {
					pad := sf.Raw[sf.BytesCovered:]
					for i, b := range pad {
						if b != 0 {
							if sf.Verified {
								t.Fatalf("sf %d non-zero pad at +%d", sf.Index, i)
							}
							break
						}
					}
				}

				if sf.Verified {
					assert.Equal(t, uint32(len(sf.Records)), sf.RecordCount,
						"sf %d count mismatch", sf.Index)
				}
			}

			if rawTotal > 0 {
				pct := 100.0 * float64(covered) / float64(rawTotal)
				assert.GreaterOrEqual(t, pct, 95.0, "overall coverage %.2f%%", pct)
			}
			assert.GreaterOrEqual(t, totalRecs, tc.minTotalRecords)
			assert.GreaterOrEqual(t, totalPaths, tc.minTotalPaths)
		})
	}
}

func TestRecordTypesAndVTNV(t *testing.T) {
	f, err := ReadFile("../resources/op7t_oem_stanvbk.img")
	require.NoError(t, err)

	var sawPath, sawItem, sawVTNV bool
	for _, sf := range f.SubFiles {
		for _, r := range sf.Records {
			if nvbk.IsPathType(r.Type) {
				sawPath = true
				assert.NotEmpty(t, r.Name)
				assert.Equal(t, byte('/'), r.Name[0])
			}
			if nvbk.IsItemType(r.Type) {
				sawItem = true
				if r.VTNV {
					sawVTNV = true
					assert.NotEmpty(t, r.Compressed)
				}
			}
		}
	}
	assert.True(t, sawPath)
	assert.True(t, sawItem)
	assert.True(t, sawVTNV)
}

func TestOplusDecodesAllSubfiles(t *testing.T) {
	f, err := ReadFile("../resources/oplusstanvbk.img")
	require.NoError(t, err)
	require.Len(t, f.SubFiles, 12)

	for _, sf := range f.SubFiles {
		assert.NotEmpty(t, sf.Records, "sf %d", sf.Index)
		assert.Equal(t, sf.RFID, sf.Records[0].RFID)
		assert.Equal(t, uint32(len(sf.Records)), sf.RecordCount)
		assert.Greater(t, len(sf.Entries)+len(sf.Items), 0, "sf %d", sf.Index)
	}
}

func TestDycDecodesNumericItems(t *testing.T) {
	f, err := ReadFile("../resources/op8pro_o2os_10.5.6.in11ba_dycnvbk_trimmed.img")
	require.NoError(t, err)
	require.Len(t, f.SubFiles, 1)

	sf := f.SubFiles[0]
	assert.Equal(t, byte(0xff), sf.RFID)
	assert.Equal(t, uint32(33), sf.RecordCount)
	assert.Len(t, sf.Records, 33)

	items := 0
	paths := 0
	for _, r := range sf.Records {
		if nvbk.IsItemType(r.Type) {
			items++
		}
		if nvbk.IsPathType(r.Type) {
			paths++
		}
	}
	assert.Greater(t, items, 10)
	assert.Greater(t, paths, 0, "dyc should also have path records")
}

func TestOEMRecordCountIsU32(t *testing.T) {
	f, err := ReadFile("../resources/oem_stanvbk-2019-10-23")
	require.NoError(t, err)
	// Previously misread as u8 hint=173; true count is 1197.
	assert.Equal(t, uint32(1197), f.SubFiles[1].RecordCount)
	assert.Len(t, f.SubFiles[1].Records, 1197)
}

func TestNoEmptyItemDataInList(t *testing.T) {
	// list/nv-get consistency: every Items entry must carry Data.
	for _, p := range []string{
		"../resources/op7t_oem_stanvbk.img",
		"../resources/oplusstanvbk.img",
		"../resources/oem_stanvbk-2019-10-23",
	} {
		f, err := ReadFile(p)
		require.NoError(t, err, p)
		for _, sf := range f.SubFiles {
			for _, it := range sf.Items {
				assert.NotEmpty(t, it.Data, "%s sf%d id=%d", p, sf.Index, it.ID)
			}
		}
	}
}

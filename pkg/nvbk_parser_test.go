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

package pkg

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseStaNVBKFileOP5TH2OS10(t *testing.T) {
	parsedFile := ReadFile("../resources/op5t_h2os_10.0.0b4_stanvbk.img")
	assert.Equal(t,116, parsedFile.Header.Total)
	assert.Equal(t,116, parsedFile.Header.Valid)
	assert.Equal(t,true, parsedFile.Header.Verify)
	assert.Equal(t,"171027", parsedFile.Header.BuildTime)
}

func TestParseDycNVBKFileOP5TH2OS10(t *testing.T) {
	parsedFile := ReadFile("../resources/op5t_h2os_10.0.0b4_dycnvbk.img")
	assert.Equal(t,1233, parsedFile.Header.Total)
	assert.Equal(t,1233, parsedFile.Header.Valid)
	assert.Equal(t,true, parsedFile.Header.Verify)
	assert.Equal(t,"191024", parsedFile.Header.BuildTime)
}

func TestParseStaNVBKFileOP8PROO2OS1056(t *testing.T) {
	parsedFile := ReadFile("../resources/op8pro_o2os_10.5.6.in11ba_stanvbk.img")
	assert.Equal(t, 86, parsedFile.Header.Total)
	assert.Equal(t, 86, parsedFile.Header.Total)
	assert.Equal(t, true, parsedFile.Header.Verify)
	assert.Equal(t, "200426", parsedFile.Header.BuildTime)
}

func TestParseDycNVBKFileOP8PROO2OS1056(t *testing.T) {
	parsedFile := ReadFile("../resources/op8pro_o2os_10.5.6.in11ba_dycnvbk.img")
	assert.Equal(t, 33, parsedFile.Header.Total)
	assert.Equal(t, 33, parsedFile.Header.Valid)
	assert.Equal(t, true, parsedFile.Header.Verify)
	assert.Equal(t, "200321", parsedFile.Header.BuildTime)
}
package nvbk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupRFIDName(t *testing.T) {
	assert.Equal(t, "manifest", LookupRFIDName(0xff))
	assert.Equal(t, "hw=1, rf=11", LookupRFIDName(0x01))
	assert.Equal(t, "hw=15, rf=55", LookupRFIDName(0xfa))
	assert.Equal(t, "", LookupRFIDName(0xfd))
}

func TestLookupNVItemName(t *testing.T) {
	// The known-name map is intentionally empty by default.
	assert.Equal(t, "", LookupNVItemName(1))
	assert.Equal(t, "", LookupNVItemName(65535))
}

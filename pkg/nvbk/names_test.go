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
	assert.Equal(t, "RFNV_LTE_CA_BW_CLASS_COMBO_I", LookupNVItemName(28874))
	assert.Equal(t, "RFNV_RF_CARD_CONFIG_I", LookupNVItemName(28967))
	assert.Equal(t, "RFNV_LTE_CA_LIST_I", LookupNVItemName(29002))
	assert.Equal(t, "ue_imei", LookupNVItemName(550))
	assert.Equal(t, "", LookupNVItemName(65535))
}

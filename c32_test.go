package codec

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimple(t *testing.T) {
	hexStrings := []string{
		"a46ff88886c2ef9762d970b4d2c63678835bd39d",
		"",
		"0000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000001",
		"1000000000000000000000000000000000000001",
		"1000000000000000000000000000000000000000",
		"01",
		"22",
		"0001",
		"000001",
		"00000001",
		"10",
		"0100",
		"1000",
		"010000",
		"100000",
		"01000000",
		"10000000",
		"0100000000",
	}
	c32Strs := []string{
		"MHQZH246RBQSERPSE2TD5HHPF21NQMWX",
		"",
		"00000000000000000000",
		"00000000000000000001",
		"20000000000000000000000000000001",
		"20000000000000000000000000000000",
		"1",
		"12",
		"01",
		"001",
		"0001",
		"G",
		"80",
		"400",
		"2000",
		"10000",
		"G0000",
		"800000",
		"4000000",
	}

	for i, hexStr := range hexStrings {
		bytes, err := hex.DecodeString(hexStr)
		assert.NoError(t, err)

		c32Encoded := c32Encode(bytes)
		assert.Equal(t, c32Strs[i], c32Encoded)
	}
}

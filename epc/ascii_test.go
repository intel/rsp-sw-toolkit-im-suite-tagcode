package epc

import (
	"fmt"
	"github.impcloud.net/RSP-Inventory-Suite/expect"
	"math/big"
	"strings"
	"testing"
)

// getASCII is an effective but inefficient algorithm to convert an assumed UTF-8
// string into its ASCII representation. Note that if the string contains invalid
// characters, the returned value is undefined.
func getASCII(s string) []byte {
	if len(s) == 0 {
		return []byte{}
	}
	// convert to binary byte string
	bitStr := fmt.Sprintf("%08b", []byte(s))
	// remove '[', ']', " "s and delete leading '0's on each byte
	bitStr = strings.ReplaceAll(bitStr[2:len(bitStr)-1], " 0", "")
	// right pad to a multiple of 8 0s
	if len(bitStr)%8 != 0 {
		bitStr += "00000000"[len(bitStr)%8:]
	}
	// use a BigInt to convert to the binary string back to bytes
	b, _ := new(big.Int).SetString(bitStr, 2)
	return b.Bytes()
}

func TestGS1ASCIIDecode(t *testing.T) {
	w := expect.WrapT(t)

	// some simple cases
	w.ShouldBeEqual(DecodeASCII([]byte{'A' << 1}), "A")
	w.ShouldBeEqual(DecodeASCII([]byte{'a' << 1}), "a")
	w.ShouldBeEqual(DecodeASCII([]byte{0x21 << 1}), "!")

	for i, s := range []string{
		"a", "A", "!",
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYXYZ",
		"0123456789",
		"\"%&/<>?",
		"",
		"aaaaaaa",
	} {
		var name string
		if len(s) <= 10 {
			name = fmt.Sprintf("TestASCIIDecode_%02d_'%s'", i, s)
		} else {
			name = fmt.Sprintf("TestASCIIDecode_%02d_'%s'...", i, s[:10])
		}
		t.Run(name, func(t *testing.T) {
			w := expect.WrapT(t)
			enc := getASCII(s)

			// validate the encoded length so we know we're doing the right thing
			expLen := len(s) * 7 / 8
			if len(s)*7%8 != 0 {
				expLen += 1
			}
			w.StopOnMismatch().
				As(fmt.Sprintf(`expected length for "%s"`, s)).
				ShouldBeEqual(expLen, len(enc))

			decoded := DecodeASCII(enc)
			if len(s)%7 == 0 && len(decoded) != 0 {
				// if the original string had a multiple of 7 characters, its
				// ASCII encoding from above includes 7 '0's padding at the end
				// (really, the final character's last bit is the first bit of
				// the last byte); as a result, we need to chop it off
				w.ShouldBeEqual(decoded[len(decoded)-1], byte(0))
				decoded = decoded[:len(decoded)-1]
			}
			w.ShouldBeEqual(decoded, s)
		})
	}
}

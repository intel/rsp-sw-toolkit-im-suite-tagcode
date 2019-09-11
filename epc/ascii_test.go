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
//
// Offset must be in [0-7]; an offset of 1 means shift the ASCII characters to
// the right by 1 bit. This has the effect of giving the first byte a number of
// leading 0s equal to the offset.
func getASCII(s string, offset uint) []byte {
	if len(s) == 0 {
		return []byte{}
	}
	// convert to binary byte string
	bitStr := fmt.Sprintf("%08b", []byte(s))
	// remove '[', ']', " "s and delete leading '0's on each byte
	bitStr = strings.ReplaceAll(bitStr[2:len(bitStr)-1], " 0", "")

	// left pad the offset (masked out later) -- panics if offset > 7
	if offset > 0 {
		bitStr = "1111111"[7-offset:] + bitStr
	}

	// right pad to a multiple of 8 0s
	if len(bitStr)%8 != 0 {
		bitStr += "00000000"[len(bitStr)%8:]
	}

	// use a BigInt to convert to the binary string back to bytes
	i, _ := new(big.Int).SetString(bitStr, 2)
	b := i.Bytes()

	// mask out the offset
	b[0] &= 0xFF >> offset
	return b
}

func TestGS1ASCIIDecode(t *testing.T) {
	for i, s := range []string{
		"a", "A", "!",
		"a!",
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYXYZ",
		"0123456789",
		"\"%&/<>?_",
		"",
		"aaaaaaa",
		"hello_world!",
	} {
		for offset := 0; offset < 8; offset++ {
			var name string
			if len(s) <= 10 {
				name = fmt.Sprintf("TestASCIIDecode_%02d_%d_'%s'", i, offset, s)
			} else {
				name = fmt.Sprintf("TestASCIIDecode_%02d_%d_'%s'...", i, offset, s[:10])
			}
			t.Run(name, func(t *testing.T) {
				w := expect.WrapT(t)
				enc := getASCII(s, uint(offset))
				w.Logf("%X", enc)

				// validate the encoded length so we know we're doing the right thing
				if offset == 0 {
					expLen := len(s) * 7 / 8
					if len(s)*7%8 != 0 {
						expLen += 1
					}
					w.StopOnMismatch().
						As(fmt.Sprintf(`expected length for "%s"`, s)).
						ShouldBeEqual(expLen, len(enc))
				}

				decoded := DecodeASCIIAt(enc, offset)
				if (offset+len(s)*7)%8 == 1 && len(decoded) != 0 {
					// if the input data had 7 trailing bits, the output will
					// have an extra null character, so we chop it off here.
					w.StopOnMismatch().ShouldBeEqual(decoded[len(decoded)-1], byte(0))
					decoded = decoded[:len(decoded)-1]
				}
				w.ShouldBeEqual(decoded, s)
			})
		}
	}
}

func TestEscapeGS1(t *testing.T) {
	escapes := []string{"%22", "%23", "%25", "%26", "%2F", "%3C", "%3E", "%3F"}
	for i, s := range []string{
		"\"", "#", "%", "&", "/", "<", ">", "?",
	} {
		name := fmt.Sprintf("OnlyChar_%02d_%q", i, s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(EscapeGS1(s), escapes[i])
		})
	}

	for i, s := range []string{
		"hello\"world", "hi#there", "lorem_% ipsum", "dolar&", "123/",
		"<open", "close>", "?..",
	} {
		name := fmt.Sprintf("InStr_%02d_%q", i, s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldContainStr(EscapeGS1(s), escapes[i])
		})
	}

	for i, s := range []string{
		"hello world", "hi there", "lorem_  ipsum", "dolar ", "123 ",
		" open", "close ", " ..",
	} {
		name := fmt.Sprintf("NoEscapes_%02d_%q", i, s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(EscapeGS1(s), s)
		})
	}

	for i, s := range []string{
		"hello\"world", "hi#there", "lorem_% ipsum", "dolar&", "123/",
		"<open", "close>", "?..",
	} {
		name := fmt.Sprintf("RoundTrip_%02d_%q", i, s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(UnescapeGS1(EscapeGS1(s)), s)
		})
	}
}

func TestUnescapeGS1(t *testing.T) {
	unescapes := []string{"\"", "#", "%", "&", "/", "<", ">", "?"}
	for i, s := range []string{
		"%22", "%23", "%25", "%26", "%2F", "%3C", "%3E", "%3F"} {
		name := fmt.Sprintf("OnlyChar_%02d_%q", i, s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(UnescapeGS1(s), unescapes[i])
		})
	}

	for i, s := range []string{
		"hello%22world", "hi%23there", "lorem_%25 ipsum", "dolar%26", "123%2F",
		"%3Copen", "close%3E", "%3F..",
	} {
		name := fmt.Sprintf("InStr_%02d_%q", i, s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldContainStr(UnescapeGS1(s), unescapes[i])
		})
	}

	for i, s := range []string{
		"hello world", "hi there", "lorem_  ipsum", "dolar ", "123 ",
		" open", "close ", " ..", "%10",
	} {
		name := fmt.Sprintf("NoEscapes_%02d_%q", i, s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(UnescapeGS1(s), s)
		})
	}

	for i, s := range []string{
		"hello%22world", "hi%23there", "lorem_%25 ipsum", "dolar%26", "123%2F",
		"%3Copen", "close%3E", "%3F..",
	} {
		name := fmt.Sprintf("RoundTrip_%02d_%q", i, s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(EscapeGS1(UnescapeGS1(s)), s)
		})
	}
}

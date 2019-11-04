/* Apache v2 license
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package epc

import (
	"fmt"
	"github.com/intel/rsp-sw-toolkit-im-suite-expect"
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

	// prepend an extra byte to keep nulls
	bitStr = "00000001" + bitStr

	// right pad to a multiple of 8 0s
	if len(bitStr)%8 != 0 {
		bitStr += "00000000"[len(bitStr)%8:]
	}

	// use a BigInt to convert to the binary string back to bytes
	i, _ := new(big.Int).SetString(bitStr, 2)
	b := i.Bytes()[1:] // ignore the first prepended byte

	// mask out the offset
	b[0] &= 0xFF >> offset
	return b
}

func TestGS1ASCIIDecode(t *testing.T) {
	for _, s := range []string{
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
			name := fmt.Sprintf("DecodeOffset_%d_%q", offset, s)
			if len(s) >= 20 {
				name = name[:20] + "..."
			}
			t.Run(name, func(t *testing.T) {
				w := expect.WrapT(t)
				enc := getASCII(s, uint(offset))

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

				decoded, n, b := DecodeASCIIAt(enc, offset)
				w.ShouldBeFalse(b)
				if (offset+len(s)*7)%8 == 1 && len(decoded) != 0 {
					w.ShouldBeEqual(n, len(decoded)-1)
					w.StopOnMismatch().ShouldBeEqual(decoded[len(decoded)-1], byte(0))
					decoded = decoded[:n]
				} else {
					w.ShouldBeEqual(n, len(decoded))
				}
				w.ShouldBeEqual(decoded, s)
			})
		}
	}
}

func TestDecodeNulls(t *testing.T) {
	for _, s := range []string{
		"\x00", "\x00\x00", "abc\x00\x00\x00",
	} {
		for offset := 0; offset < 8; offset++ {
			var name string
			name = fmt.Sprintf("NullTerminated_%d_%q", offset, s)
			t.Run(name, func(t *testing.T) {
				w := expect.WrapT(t)
				enc := getASCII(s, uint(offset))
				decoded, n, b := DecodeASCIIAt(enc, offset)
				w.ShouldNotBeEmptyStr(decoded)
				w.As(n).ShouldBeTrue(n <= len(s)+1)
				w.As(n).ShouldBeTrue(n <= len(enc))
				w.ShouldBeFalse(b)
			})
		}
	}

	for _, s := range []string{
		"\x00a", "\x00a\x00", "a\x00b\x00c\x00",
	} {
		for offset := 0; offset < 8; offset++ {
			var name string
			name = fmt.Sprintf("CharAfterNull_%d_%q", offset, s)
			t.Run(name, func(t *testing.T) {
				w := expect.WrapT(t)
				enc := getASCII(s, uint(offset))
				decoded, n, b := DecodeASCIIAt(enc, offset)
				w.ShouldNotBeEmptyStr(decoded)
				w.ShouldBeTrue(n <= len(s)+1)
				w.ShouldBeTrue(b)
			})
		}
	}
}

func TestEscapeGS1(t *testing.T) {
	escapes := []string{"%22", "%23", "%25", "%26", "%2F", "%3C", "%3E", "%3F"}
	for i, s := range []string{
		"\"", "#", "%", "&", "/", "<", ">", "?",
	} {
		name := fmt.Sprintf("OnlyChar_%q", s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(EscapeGS1(s), escapes[i])
		})
	}

	for i, s := range []string{
		"hello\"world", "hi#there", "lorem_% ipsum", "dolar&", "123/",
		"<open", "close>", "?..",
	} {
		name := fmt.Sprintf("InStr_%q", s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldContainStr(EscapeGS1(s), escapes[i])
		})
	}

	for _, s := range []string{
		"hello world", "hi there", "lorem_  ipsum", "dolar ", "123 ",
		" open", "close ", " ..",
	} {
		name := fmt.Sprintf("NoEscapes_%q", s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(EscapeGS1(s), s)
		})
	}

	for _, s := range []string{
		"hello\"world", "hi#there", "lorem_% ipsum", "dolar&", "123/",
		"<open", "close>", "?..",
	} {
		name := fmt.Sprintf("RoundTrip_%q", s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(UnescapeGS1(EscapeGS1(s)), s)
		})
	}
}

func TestUnescapeGS1(t *testing.T) {
	unescapes := []string{"\"", "#", "%", "&", "/", "<", ">", "?"}
	for i, s := range []string{
		"%22", "%23", "%25", "%26", "%2F", "%3C", "%3E", "%3F"} {
		name := fmt.Sprintf("OnlyChar_%q", s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(UnescapeGS1(s), unescapes[i])
		})
	}

	for i, s := range []string{
		"hello%22world", "hi%23there", "lorem_%25 ipsum", "dolar%26", "123%2F",
		"%3Copen", "close%3E", "%3F..",
	} {
		name := fmt.Sprintf("InStr_%q", s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldContainStr(UnescapeGS1(s), unescapes[i])
		})
	}

	for _, s := range []string{
		"hello world", "hi there", "lorem_  ipsum", "dolar ", "123 ",
		" open", "close ", " ..", "%10",
	} {
		name := fmt.Sprintf("NoEscapes_%q", s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(UnescapeGS1(s), s)
		})
	}

	for _, s := range []string{
		"hello%22world", "hi%23there", "lorem_%25 ipsum", "dolar%26", "123%2F",
		"%3Copen", "close%3E", "%3F..",
	} {
		name := fmt.Sprintf("RoundTrip_%q", s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeEqual(EscapeGS1(UnescapeGS1(s)), s)
		})
	}
}

func TestIsGS1AIEncodable(t *testing.T) {
	// all valid chars + null
	valid := `!"%&'()*+,-./:;<=>?_0123456789` +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\x00"

	for _, s := range valid[:len(valid)-1] {
		name := fmt.Sprintf("IndividualChar_%q", s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeTrue(IsGS1AIEncodable(string(s)))
		})
	}

	// all of these are valid SGTIN-198 serials
	for _, s := range []string{
		"", `"Hello_World!"`, "1&2", "lorem_%%ipsum", "123//4567890",
		"<<open", "close>>", "...==?!?!?!?", "''_(--)_//", `/`, "+++---+++",
		":)*****;)******:,(", "hello_world!\x00\x00\x00\x00\x00\x00",
		"\x00\x00",
	} {
		name := fmt.Sprintf("ValidStrs_%q", s)
		t.Run(name, func(t *testing.T) {
			w := expect.WrapT(t)
			w.ShouldContain(valid, s) // same validation, but slow
			w.ShouldBeTrue(IsGS1AIEncodable(s))
		})
	}

	for _, s := range []string{
		" ", `"Hello World!"`, "lorem~~ipsum", "#",
		"\u1234", "HELLO\x00WORLD", "\x01", "\x80", "with\nbreak",
		"$$&&$$", "A@B.com", "insert[here]", "^_^", "`", ":{", "|", "}",
	} {
		name := fmt.Sprintf("InvalidStrs_%q", s)
		t.Run(name, func(t *testing.T) {
			w := expect.WrapT(t)
			w.ShouldBeFalse(IsGS1AIEncodable(s))
		})
	}
}

func TestIsGS1CompPartEncable(t *testing.T) {
	// valid chars, plus null
	valid := `#-/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ` + "\x00"

	for _, s := range valid[:len(valid)-1] {
		name := fmt.Sprintf("IndividualChar_%q", s)
		t.Run(name, func(t *testing.T) {
			expect.WrapT(t).ShouldBeTrue(IsGS1CompPartEncodable(string(s)))
		})
	}

	for _, s := range []string{
		"", `HELLO-WORLD`, "---////---", "###1234567890###",
		"HELLO-WORLD\x00\x00", "\x00\x00",
	} {
		name := fmt.Sprintf("ValidStrs_%q", s)
		t.Run(name, func(t *testing.T) {
			w := expect.WrapT(t)
			w.ShouldContain(valid, s) // same validation, but slow
			w.ShouldBeTrue(IsGS1CompPartEncodable(s))
		})
	}

	for _, s := range []string{
		"!", `"`, "%", "&", "'", "(", ")", "*", "+", ",", ".",
		" ", `"Hello_World!"`, "lorem~~ipsum",
		"\u1234", "HELLO\x00WOLRD", "\x01", "\x80", "with\nbreak",
		"$$&&$$", "A@B.com", "insert[here]", "^_^", "`", ":{", "|", "}",
	} {
		name := fmt.Sprintf("InvalidStrs_%q", s)
		t.Run(name, func(t *testing.T) {
			w := expect.WrapT(t)
			w.ShouldBeFalse(IsGS1CompPartEncodable(s))
		})
	}
}

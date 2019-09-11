package epc

import (
	"fmt"
	"github.impcloud.net/RSP-Inventory-Suite/tagcode/bitextract"
	"strings"
)

var (
	asciiExtracts = []bitextract.BitExtractor{
		bitextract.New(0, 7),
		bitextract.New(7, 7),
		bitextract.New(6, 7),
		bitextract.New(5, 7),
		bitextract.New(4, 7),
		bitextract.New(3, 7),
		bitextract.New(2, 7),
		bitextract.New(1, 7),
	}

	gs1Escaper = strings.NewReplacer(
		`"`, "%22",
		`#`, "%23",
		`%`, "%25",
		`&`, "%26",
		`/`, "%2F",
		`<`, "%3C",
		`>`, "%3E",
		`?`, "%3F",
	)

	gs1Unescaper = strings.NewReplacer(
		"%22", `"`,
		"%23", `#`,
		"%25", `%`,
		"%26", `&`,
		"%2F", `/`,
		"%3C", `<`,
		"%3E", `>`,
		"%3F", `?`,
	)

	// valid characters for GS1 Application Identifiers
	gs1AICharSet = [127]uint8{
		'!': 1, '"': 1, '%': 1, '&': 1, '\'': 1, '(': 1, ')': 1,
		'*': 1, '+': 1, ',': 1, '-': 1, '.': 1, '/': 1,
		':': 1, ';': 1, '<': 1, '=': 1, '>': 1, '?': 1, '_': 1,
		'0': 1, '1': 1, '2': 1, '3': 1, '4': 1, '5': 1, '6': 1, '7': 1, '8': 1, '9': 1,
		'A': 1, 'B': 1, 'C': 1, 'D': 1, 'E': 1, 'F': 1, 'G': 1, 'H': 1, 'I': 1,
		'J': 1, 'K': 1, 'L': 1, 'M': 1, 'N': 1, 'O': 1, 'P': 1, 'Q': 1, 'R': 1,
		'S': 1, 'T': 1, 'U': 1, 'V': 1, 'W': 1, 'X': 1, 'Y': 1, 'Z': 1,
		'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1, 'f': 1, 'g': 1, 'h': 1, 'i': 1,
		'j': 1, 'k': 1, 'l': 1, 'm': 1, 'n': 1, 'o': 1, 'p': 1, 'q': 1, 'r': 1,
		's': 1, 't': 1, 'u': 1, 'v': 1, 'w': 1, 'x': 1, 'y': 1, 'z': 1,
	}

	// valid characters for GS1 Application Identifiers for Component and Parts
	gs1AICPCharSet = [127]uint8{
		'#': 1, '-': 1, '/': 1,
		'0': 1, '1': 1, '2': 1, '3': 1, '4': 1, '5': 1, '6': 1, '7': 1, '8': 1, '9': 1,
		'A': 1, 'B': 1, 'C': 1, 'D': 1, 'E': 1, 'F': 1, 'G': 1, 'H': 1, 'I': 1,
		'J': 1, 'K': 1, 'L': 1, 'M': 1, 'N': 1, 'O': 1, 'P': 1, 'Q': 1, 'R': 1,
		'S': 1, 'T': 1, 'U': 1, 'V': 1, 'W': 1, 'X': 1, 'Y': 1, 'Z': 1,
	}
)

// DecodeASCII decodes 7-bit ISO-646 packed ASCII bit strings into their UTF-8
// representations.
//
// This function expects the first bit of the first character to be the first
// bit of the first byte of the input. If the first bit of the first character
// is offset within the first byte, use DecodeASCIIAt(data, offset).
//
// Essentially, this just expands the input such that every consecutive run of
// 7 bits is placed into its own byte with a leading 0. Note that as far as this
// function is concerned, there are no invalid inputs.
//
// If the incoming data isn't a multiple of 7 bits, the final bits are ignored,
// and the string will have floor(len(data)*8/7) characters.
//
// If the original string had a multiple of 7 ASCII characters, the final data
// byte's most significant bit is the final ASCII bit, but the remaining 7 bits
// are indistinguishable from any other ASCII character; thus, the returned
// string will have an extra character relative the original ASCII string. Since
// Go allows 0x00 in strings, this is true even if the final bits are all 0s.
// The best way to handle this is to slice the returned string to the number of
// characters in the expected output.
//
// An empty or nil input results in an empty return string.
func DecodeASCII(data []byte) string {
	return DecodeASCIIAt(data, 0)
}

// DecodeASCIIAt works like DecodeASCII, but expects the bit of the first ASCII
// character to start at the bit offset within the first byte.
//
// E.g., DecodeASCIIAt(data, 2) expects the first ASCII character to start at
// bit 2; bits 0 & 1 of byte 0 are skipped, then bits 2-7 of byte 0 are combined
// with bit 0 of byte 1 and inserted into the output byte 0, bits 1-7 (bit 0 of
// ASCII bytes are always 0).
//
// Panics if the offset isn't in [0, 7].
func DecodeASCIIAt(data []byte, offset int) string {
	if offset < 0 || offset > 7 {
		panic(fmt.Errorf("invalid offset %d", offset))
	}

	outbyteLen := ((len(data) * 8) - offset) / 7
	if outbyteLen <= 0 {
		return ""
	}

	ext := (8 - offset) % 8
	outdata := make([]byte, outbyteLen)
	for i := 0; i < len(outdata); i++ {
		inbyte := i - ((i + 7 - offset) / 8)
		asciiExtracts[ext%8].ExtractTo(outdata[i:], data[inbyte:])
		ext++
	}
	return string(outdata)
}

// EscapeGS1 returns s with the following characters replaced by their GS1
// escape sequences:
// - `"` -> "%22"
// - `#` -> "%23" (note: only valid for AI Component and Parts)
// - `%` -> "%25"
// - `&` -> "%26"
// - `/` -> "%2F"
// - `<` -> "%3C"
// - `>` -> "%3E"
// - `?` -> "%3F"
func EscapeGS1(s string) string {
	return gs1Escaper.Replace(s)
}

// UnescapeGS1 returns s with the following escape sequences replaced by their
// GS1 character equivalents.
// - `"` -> "%22"
// - `#` -> "%23" (note: only valid for AI Component and Parts)
// - `%` -> "%25"
// - `&` -> "%26"
// - `/` -> "%2F"
// - `<` -> "%3C"
// - `>` -> "%3E"
// - `?` -> "%3F"
func UnescapeGS1(s string) string {
	return gs1Unescaper.Replace(s)
}

// IsGS1Alphanumeric returns true if the string contains only characters allowed
// in GS1 Application Identifier character set.
func IsGS1AIEncodable(s string) bool {
	for i := range s {
		if !(s[i] <= 127 && gs1AICharSet[s[i]&0x7F] == 1) {
			return false
		}
	}
	return true
}

// IsGS1CompPartEncodable returns true if the string contains only characters
// allowed in the GS1 Application Identifier for Component and Parts character set.
func IsGS1CompPartEncodable(s string) bool {
	for i := range s {
		if !(s[i] <= 127 && gs1AICPCharSet[s[i]&0x7F] == 1) {
			return false
		}
	}
	return true
}

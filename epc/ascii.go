/*
 * INTEL CONFIDENTIAL
 * Copyright (2019) Intel Corporation.
 *
 * The source code contained or described herein and all documents related to the source code ("Material")
 * are owned by Intel Corporation or its suppliers or licensors. Title to the Material remains with
 * Intel Corporation or its suppliers and licensors. The Material may contain trade secrets and proprietary
 * and confidential information of Intel Corporation and its suppliers and licensors, and is protected by
 * worldwide copyright and trade secret laws and treaty provisions. No part of the Material may be used,
 * copied, reproduced, modified, published, uploaded, posted, transmitted, distributed, or disclosed in
 * any way without Intel/'s prior express written permission.
 * No license under any patent, copyright, trade secret or other intellectual property right is granted
 * to or conferred upon you by disclosure or delivery of the Materials, either expressly, by implication,
 * inducement, estoppel or otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 * Unless otherwise agreed by Intel in writing, you may not remove or alter this notice or any other
 * notice embedded in Materials by Intel or Intel's suppliers or licensors in any way.
 */

package epc

import (
	"fmt"
	"github.com/intel/rsp-sw-toolkit-im-suite-tagcode/bitextract"
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
		"\x00", "",
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
// representations, starting at the given bit offset.
//
// E.g., DecodeASCIIAt(data, 2) expects the first ASCII character to start at
// bit 2; bits 0 & 1 of byte 0 are skipped, then bits 2-7 of byte 0 are combined
// with bit 0 of byte 1 and inserted into the output byte 0, bits 1-7 (bit 0 of
// ASCII bytes are always 0).
//
// Essentially, this just expands the input such that every consecutive run of
// 7 bits is placed into its own byte with a leading 0. Note that as far as this
// function is concerned, there are no invalid inputs.
//
// If the incoming data isn't a multiple of 7 bits, the final bits are ignored,
// and the string will have floor(len(data)*8/7) characters.
//
// The returned values are the UTF-8 string, the number of chars before a null
// byte, and whether there are any non-null characters after a null terminator.
// Given the output (s, n, b), s[:n] is the slice of characters up to but not
// including the first null terminator, regardless of whether it had a null byte
// or extra characters following it.
//
// The function panics if the offset isn't in [0, 7].
// An empty or nil input returns ("", 0).
func DecodeASCIIAt(data []byte, offset int) (out string, nullTerm int, extra bool) {
	if offset < 0 || offset > 7 {
		panic(fmt.Errorf("invalid offset %d", offset))
	}

	outbyteLen := ((len(data) * 8) - offset) / 7
	if outbyteLen <= 0 {
		return "", 0, len(data) == 1 && data[0] != nullASCII
	}

	nullTerm = -1
	ext := (8 - offset) % 8
	outdata := make([]byte, outbyteLen)
	for i := 0; i < len(outdata); i++ {
		inbyte := i - ((i + 7 - offset) / 8)
		asciiExtracts[ext%8].ExtractTo(outdata[i:], data[inbyte:])
		ext++

		if outdata[i] == nullASCII {
			if nullTerm == -1 {
				nullTerm = i
			}
		} else if nullTerm != -1 {
			extra = true
		}
	}
	out = string(outdata)
	if nullTerm == -1 {
		nullTerm = len(out)
	}
	return
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
//
// Additionally, removes null bytes. This function doesn't validate that the
// character sequence is necessarily valid, since it may contain characters or
// sequences that aren't otherwise valid.
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
//
// This function doesn't validate that the character sequence is valid.
func UnescapeGS1(s string) string {
	return gs1Unescaper.Replace(s)
}

const nullASCII = '\x00'

// IsGS1Alphanumeric returns true if the string contains only characters allowed
// in GS1 Application Identifier character set, or null bytes NOT followed by
// any non-null byte.
func IsGS1AIEncodable(s string) bool {
	for i := range s {
		// null may only be followed by null
		if s[i] == nullASCII {
			for i++; i < len(s); i++ {
				if s[i] != nullASCII {
					return false
				}
			}
		} else if !(s[i] <= 127 && gs1AICharSet[s[i]&0x7F] == 1) {
			return false
		}
	}
	return true
}

// IsGS1CompPartEncodable returns true if the string contains only characters
// allowed in the GS1 Application Identifier for Component and Parts character
// set, or null bytes NOT followed by any non-null byte.
func IsGS1CompPartEncodable(s string) bool {
	for i := range s {
		// null may only be followed by null
		if s[i] == nullASCII {
			for i++; i < len(s); i++ {
				if s[i] != nullASCII {
					return false
				}
			}
		} else if !(s[i] <= 127 && gs1AICPCharSet[s[i]&0x7F] == 1) {
			return false
		}
	}
	return true
}

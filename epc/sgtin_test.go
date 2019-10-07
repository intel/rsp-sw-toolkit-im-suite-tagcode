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
	"github.impcloud.net/RSP-Inventory-Suite/expect"
	"math"
	"math/rand"
	"testing"
)

func TestDecodeSGTIN(t *testing.T) {
	type sgtinTest struct {
		name, epc, uri, gtin string
		badCode, badRange    bool
	}

	pass := func(n, e, g, u string) sgtinTest {
		return sgtinTest{
			name: n,
			epc:  e,
			gtin: g,
			uri:  u,
		}
	}

	fail := func(n, e string) sgtinTest {
		return sgtinTest{
			name:    n,
			epc:     e,
			badCode: true,
		}
	}

	badRange := func(n, e string) sgtinTest {
		return sgtinTest{
			name:     n,
			epc:      e,
			badRange: true,
		}
	}

	for i, tt := range []sgtinTest{
		pass("partition0", "300000000000044000000001",
			"10000000000014", "000000000001.1.1"),
		pass("partition1", "300400000000204000000001",
			"00000000000116", "00000000001.01.1"),
		pass("partition2", "300800000001004000000001",
			"00000000001014", "0000000001.001.1"),
		pass("partition3", "300C00000010004000000001",
			"00000000010016", "000000001.0001.1"),
		pass("partition4", "301000000080004000000001",
			"00000000100014", "00000001.00001.1"),
		pass("partition5", "301400000400004000000001",
			"00000001000016", "0000001.000001.1"),
		pass("partition6", "301800004000004000000001",
			"00000010000014", "000001.0000001.1"),

		pass("company prefix 0", "301800000000004000000001",
			"00000000000017", "000000.0000001.1"),
		pass("item ref 0", "301800004000000000000001",
			"00000010000007", "000001.0000000.1"),

		pass("UPC-A", "30143639F84191AD22901607",
			"00888446671424", "0888446.067142.193853396487"),
		pass("UPC-A", "3034257BF400B7800004CB2F",
			"00614141007349", "0614141.000734.314159"),
		pass("indicator 4", "300000662D3D311048C6D8D9",
			"40004285602049", "000428560204.4.69940467929"),
		pass("indicator 1", "3000011B896A506B29C18539",
			"10011892394440", "001189239444.1.185384142137"),

		pass("SGTIN-198-numeric", "36143639F8419198B966E1AB366E5B3470DC00000000000000",
			"00888446671424", "0888446.067142.193853396487"),
		pass("SGTIN-198-alpha", "36143639F84191A465D9B37A176C5EB1769D72E557D52E5CBC",
			"00888446671424", "0888446.067142.Hello!;1=1;'..*_*..%2F"),

		fail("Unknown header", "E2801160600002054CC2096F"),
		fail("Too long for SGTIN-96", "30180000400000400000000011"),
		fail("Too Short for SGTIN-96", "3018000040000040000000"),
		fail("Too long for SGTIN-198", "36143639F84191A465D9B37A176C5EB1769D72E557D52E5CBADDFC"),
		fail("Too short for SGTIN-198", "36143636C5EB1769D72E557D52E5CBADDFC"),
		fail("Partition value should be <=6", "301C00004000004000000001"),

		badRange("Item reference out of range", "301000181C2CC193A8B43711"),
		badRange("Item reference out of range", "361000181C2CC1A465D9B37A176C5EB1769D72E557D52E5CBC"),
		badRange("Item reference out of range", "30244032EACFF145202001E8"),
		badRange("Item reference out of range", "36244032EACFF1A465D9B37A176C5EB1769D72E557D52E5CBC"),
		badRange("SGTIN-198 serial with chars after null", "36044032EAC191A465D9B37A176C5EB1769D72E557D5200CBC"),
	} {
		t.Run(fmt.Sprintf("%02d_%s", i, tt.name), func(t *testing.T) {
			w := expect.WrapT(t)

			s, err := DecodeSGTINString(tt.epc)
			if tt.badCode {
				w.Logf("%+v", err)
				w.As(tt.epc).ShouldFail(err)
				return
			}

			w.As(tt.epc).ShouldSucceed(err)

			if tt.badRange {
				err = w.As(fmt.Sprintf("%s: %+v", tt.epc, s)).ShouldFail(s.ValidateRanges())
				w.Logf("%+v", err)
			} else {
				w.ShouldBeEqual(s.GTIN(), tt.gtin)
				w.ShouldBeEqual(s.URI(), SGTINPureURIPrefix+":"+tt.uri)
			}
		})
	}
}

func TestCheckDigit_0to9(t *testing.T) {
	// verify the check digit is always 0-9, regardless of input
	s := SGTIN{}
	for i := 0; i < 1000; i++ {
		s.itemRef = rand.Int() % 1000000
		c := s.checkDigit()
		if c < 0 || c > 9 {
			t.Errorf("bad check digit for %d: %d", s.itemRef, c)
		}
	}
}

func TestCheckDigit_properties(t *testing.T) {
	// We can easily confirm the CD for when the GTIN has 1 non-zero digit; note
	// that '0' is impossible: the "sum" of 1 digit (0-9) cannot be 10. If the
	// digit d is in an even position, the check digit is just 10-d;
	// for the odd digit positions, it's 10-(3*d):
	oddCDs := []int{7, 4, 1, 8, 5, 2, 9, 6, 3}
	expected := func(digitVal, digitPosition int) int {
		// 1='ones place' means check 1, 2, ..., 9: these are 'odds'
		// 2='tens place' means check 10, 20, ... 90: these are 'evens'
		if digitPosition&1 == 0 {
			return 10 - digitVal
		}
		return oddCDs[digitVal-1]
	}

	w := expect.WrapT(t)
	s := SGTIN{serial: "0"}
	// the check digit pattern explained above should be true regardless of the
	// partition value, whether the relevant digit is in the item ref, company
	// prefix, or is the indicator digit -- so we'll confirm that's true
	// (note: the max company prefix/item ref does depend on the partition)
	for partition := 0; partition <= 6; partition++ {
		s.partition = partition
		for digit := 1; digit < 10; digit++ {
			// validate when digit is in company prefix
			for digitPlace := 1; digitPlace <= 12-partition; digitPlace++ {
				factor := int(math.Pow10(digitPlace - 1)) // 1, 10, 100, etc.
				s.companyPrefix = digit * factor          // 1, 2, ..., 9, 10, 20, 30, ..., 90, 100, 200, etc.
				w.StopOnMismatch().ShouldSucceed(s.ValidateRanges())
				c := s.checkDigit()
				w.As(fmt.Sprintf("check digit for company prefix: %d, digit %d, partition %d",
					s.companyPrefix, digitPlace, partition)).
					ShouldBeEqual(c, expected(digit, digitPlace-partition))
			}
			s.companyPrefix = 0

			// validate when digit is in item ref; note that digitPlaces <= partition
			for digitPlace := 1; digitPlace <= partition; digitPlace++ {
				factor := int(math.Pow10(digitPlace - 1)) // 1, 10, 100, etc.
				s.itemRef = digit * factor                // 1, 2, ..., 9, 10, 20, 30, ..., 90, 100, 200, etc.
				w.StopOnMismatch().ShouldSucceed(s.ValidateRanges())
				c := s.checkDigit()
				w.As(fmt.Sprintf("check digit for item ref: %d, digit %d, partition %d",
					s.itemRef, digitPlace, partition)).
					ShouldBeEqual(c, expected(digit, digitPlace))
			}
			s.itemRef = 0

			// validate when digit is the indicator (digit 13)
			s.indicator = digit
			c := s.checkDigit()
			w.As(fmt.Sprintf("check digit for indicator: %d, partition %d",
				s.indicator, partition)).
				ShouldBeEqual(c, expected(digit, 13))
			s.indicator = 0
		}
	}
}

func TestSGTIN_CanSGTIN96(t *testing.T) {
	type test struct {
		name   string
		serial string
		valid  bool
	}

	pass := func(name, serial string) test {
		return test{name: name, serial: serial, valid: true}
	}
	fail := func(name, serial string) test {
		return test{name: name, serial: serial, valid: false}
	}

	for i, tt := range []test{
		pass("Leading '0'", "0"),
		pass("1", "1"),
		pass("10", "10"),
		pass("Largest", "274877906943"),

		fail("Empty", ""),
		fail("Non-numeric", "A1"),
		fail("Leading '0' 1", "00"),
		fail("Leading '0' 2", "000"),
		fail("Leading '0' 3", " 0"),
		fail("Leading '0' 4", "01"),
	} {
		t.Run(fmt.Sprintf("%02d_%s", i, tt.name), func(t *testing.T) {
			w := expect.WrapT(t)
			err := SGTIN{serial: tt.serial}.CanSGTIN96()
			if tt.valid {
				w.ShouldSucceed(err)
			} else {
				w.ShouldFail(err)
			}
		})
	}
}

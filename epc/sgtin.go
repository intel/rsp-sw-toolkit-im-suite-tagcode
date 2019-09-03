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
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"github.impcloud.net/RSP-Inventory-Suite/tagcode/bitextract"
	"strconv"
)

const (
	SGTINPureURIPrefix = "urn:epc:id:sgtin"
	SGTIN96NumBytes    = 12
	SGTIN198NumBytes   = 25 // 198 bits are not byte-aligned
	SGTIN96Header      = 0x30
	SGTIN198Header     = 0x36
)

// SGTIN does not directly correspond to a GS1 identifier, but instead is a
// combination of a GS1 GTIN (global trade identification number) and a serial
// "number" to identify the specific instance of that GTIN.
//
// Although the serial value is frequently referenced as a serial "number", the
// GS1 General Specifications permits _alphanumeric_ serial numbers, not just
// the digits 0-9. Moreover, it specifies that those serial *must* be treated
// as a string, wherein two serials are distinct if their string comparisons are
// distinct, including leading '0's. In other words, '0', '07', '007' are all
// valid, distinct serial numbers. On the other hand, the EPC Tag Standard
// restricts some serial number depending on the encoding. Specifically, SGTIN-96
// only permits serial numbers consisting of digits '0'-'9', and forbids serials
// with leading '0's, except for a single '0'. SGTIN-198 has no such restriction.
//
// As a result, '000' is a valid SGTIN serial number, but cannot be encoded in
// in SGTIN-96 format. Furthermore, in the URI representation of EPCs containing
// serials with non-numeric characters, certain characters must be percent-
// encoded according to the ISO 646 (ASCII) character code. Essentially, this
// means they take the form "%XX" where XX is their hexadecimal value. These
// substitutions are made for the following characters:
//     Graphic | URI Percent Encoding
//       "          %22
//       %          %25
//       &          %26
//       /          %2F
//       <          %3C
//       >          %3E
//       ?          %3F
//
// Although the company prefix and item reference are, in principle, strings
// with relevant leading '0's, their partition value unambiguously identifies
// their permissible values, and so for ease of use, they are represented as
// integer values.
type SGTIN struct {
	// filter and partition are features of the tag encodings of SGTINs
	filter    FilterValue
	partition int

	companyPrefix int
	indicator     int
	itemRef       int
	serial        string
}

// NewSGTIN returns an SGTIN structure with the given values and, potentially,
// an error if the given set of values are inconsistent with the SGTIN standard.
func NewSGTIN(filter FilterValue, partition, indicator, companyPrefix, itemRef int, serial string) (SGTIN, error) {
	s := SGTIN{
		filter:        filter,
		partition:     partition,
		indicator:     indicator,
		companyPrefix: companyPrefix,
		itemRef:       itemRef,
		serial:        serial,
	}
	return s, s.ValidateRanges()
}

// DecodeSGTINString accepts a big endian, hex-encoded SGTIN EPC and returns
// its SGTIN representation, or an error if it cannot be decoded as such.
//
// The SGTIN's values are NOT validated; use SGTIN.ValidateRanges() to determine
// whether it is compliant with the GS1/EPC Tag Data Standards.
func DecodeSGTINString(epc string) (SGTIN, error) {
	b, err := hex.DecodeString(epc)
	if err != nil {
		return SGTIN{}, err
	}
	return DecodeSGTIN(b)
}

// SGTINToGTIN14 is a convenience method for decoding an SGTIN encoded EPC
// from a big-endian, hex string to its corresponding GS1 GTIN element string.
func SGTINToGTIN14(epc string) (string, error) {
	sgtin, err := DecodeSGTINString(epc)
	if err != nil {
		return "", err
	}
	if err := sgtin.ValidateRanges(); err != nil {
		return "", err
	}
	return sgtin.GTIN(), nil
}

// SGTINToPureURI is a convenience method for decoding an SGTIN encoded EPC
// from a big-endian, hex string to its corresponding GS1 Pure Identity URI.
func SGTINToPureURI(epc string) (string, error) {
	sgtin, err := DecodeSGTINString(epc)
	if err != nil {
		return "", err
	}
	if err := sgtin.ValidateRanges(); err != nil {
		return "", err
	}
	return sgtin.URI(), nil
}

// ValidateRanges checks an SGTIN's values to ensure they fit the range
// restrictions of their respective fields.
//
// Note that GS1 and EPCGlobal standards restrict many potential values that
// would otherwise fit within their relevant fields (for example, RCNs with GS1
// Prefix '02' are not valid GTINs and should not be encoded to SGTIN); this
// method only validates that they fit within the available ranges, but not that
// they are otherwise legal.
func (sgtin SGTIN) ValidateRanges() error {
	if sgtin.indicator < 0 || sgtin.indicator > 9 {
		return errors.Errorf("invalid indicator: %d", sgtin.indicator)
	}
	if sgtin.partition < 0 || sgtin.partition > 6 {
		return errors.Errorf("invalid partition: %d", sgtin.partition)
	}
	if sgtin.itemRef < 0 || sgtin.itemRef > maxItems[sgtin.partition]-1 {
		return errors.Errorf("item refs in partition %d must be in [0, %d], "+
			"but is %d", sgtin.partition, maxItems[sgtin.partition]-1, sgtin.itemRef)
	}
	if sgtin.companyPrefix < 0 || sgtin.companyPrefix > maxPrefix[sgtin.partition] {
		return errors.Errorf("company prefix in partition %d must be in [0, %d], "+
			"but is %d", sgtin.partition, maxPrefix[sgtin.partition], sgtin.companyPrefix)
	}
	if sgtin.serial == "" {
		return errors.New("serial is empty")
	}
	if len(sgtin.serial) > 20 {
		return errors.Errorf("SGTIN serial numbers are limited to at most "+
			"20 characters, but this serial has %d characters", len(sgtin.serial))
	}
	return nil
}

// CanSGTIN96 returns true if the SGTIN's serial may be encoded as SGTIN-96.
//
// The EPC Tag Data Standard specifies that SGTIN-96 encoded serial numbers must
// consist only of decimal values (0-9) less than 2^(38), with no leading '0's,
// except for a single '0'.
func (sgtin SGTIN) CanSGTIN96() error {
	if sgtin.serial == "" {
		return errors.New("serial is empty")
	}
	_, err := strconv.ParseUint(sgtin.serial, 10, 38)
	if err != nil {
		return err
	}
	if sgtin.serial[0] == '0' && sgtin.serial != "0" {
		return errors.New("serials cannot have leading '0's, " +
			"except for the unique value '0'")
	}
	return nil
}

// GTIN returns the GS1 GTIN element string represented by this SGTIN.
func (sgtin SGTIN) GTIN() string {
	if sgtin.partition == 0 {
		// no item reference
		return fmt.Sprintf("%d%012d%d",
			sgtin.indicator,
			sgtin.companyPrefix,
			sgtin.checkDigit())
	}
	return fmt.Sprintf("%d%0[2]*d%0[4]*d%d",
		sgtin.indicator,
		12-sgtin.partition, sgtin.companyPrefix,
		sgtin.partition, sgtin.itemRef,
		sgtin.checkDigit())
}

// URI returns the EPC Pure Identity URI for this SGTIN, of the format:
//     urn:epc:id:sgtin:CompanyPrefix.ItemRefAndIndicator.SerialNumber
func (sgtin SGTIN) URI() string {
	if sgtin.partition == 0 {
		// no item reference; just indicator
		return fmt.Sprintf("%s:%0[2]*d.%d.%s",
			SGTINPureURIPrefix,
			12-sgtin.partition, sgtin.companyPrefix,
			sgtin.indicator,
			sgtin.serial)
	}
	return fmt.Sprintf("%s:%0[2]*d.%d%0[5]*d.%s",
		SGTINPureURIPrefix,
		12-sgtin.partition, sgtin.companyPrefix,
		sgtin.indicator, sgtin.partition, sgtin.itemRef,
		sgtin.serial)
}

// checkSum returns the portion of the GS1 check sum that n contributes, given
// that n's lowest digit is in position d1.
//
// This function allows calculating the checksum of a number in pieces, from
// which the check digit is equal to ((10 - sum(parts)%10) % 10).
//
// d1 is 1-indexed position of the smallest digit of n. That is, d1 is where the
// "ones place" of n lies within the number containing it, as counted from the
// "ones place" of that number. Do not include the final check digit.
//
// Example: if you wanted the check digit C of 01234C, and had the value stored
//          in three parts: 01 | 234 | C, you could use the function to get the
//          checkSum of the first two parts by considering the "total" number as
//          "01234", in which "234"'s 1's place is at d1=1 and "01"'s d1=4. Then
//          the sum = checkSum(234, 1) + checkSum(1, 4), and C=((10-sum%10)%10).
//
// d1 is used to determine which digits are odd and which digits are even, and
// in principle, it doesn't matter what number you enter, so long as it matches
// to the correct class.
func checkSum(n, d1 int) (sum int) {
	for i := 0; n > 0; i++ {
		sum += (n % 10) * ((((d1 - i) & 1) << 1) | 1)
		n /= 10
	}
	return
}

// checkDigit returns the GS1 check digit of the underlying GTIN value
func (sgtin SGTIN) checkDigit() int {
	sum := checkSum(sgtin.itemRef, 1) +
		checkSum(sgtin.companyPrefix, 13-sgtin.partition) +
		checkSum(sgtin.indicator, 13)

	// mod 10 additive inverse
	return (10 - (sum % 10)) % 10
}

const (
	gcpStartBit    = 8 + 3 + 3        // header + filter + partition
	serialStartBit = gcpStartBit + 44 // company prefix + IIR field
)

var (
	filterExt    = bitextract.New(8, 3)
	partitionExt = bitextract.New(11, 3)
	serial96Ext  = bitextract.New(58, 38)
	serial198Ext = bitextract.New(58, 140)

	// which bits are the company prefix and which are the indicator/item ref
	// depend on the partition; the whole space is 44 bits wide, but divided
	// between them in a way that allocates 10^(12-partition) values to the
	// company prefix and 10^(partition-1) values to the IIR field; note that
	// because the indicator is required, partition 0 does not allow any items.
	companyExt = [7]bitextract.BitExtractor{
		bitextract.New(gcpStartBit, 40),
		bitextract.New(gcpStartBit, 37),
		bitextract.New(gcpStartBit, 34),
		bitextract.New(gcpStartBit, 30),
		bitextract.New(gcpStartBit, 27),
		bitextract.New(gcpStartBit, 24),
		bitextract.New(gcpStartBit, 20),
	}
	// indicator digit + item ref
	iirExt = [7]bitextract.BitExtractor{
		bitextract.New(serialStartBit-4, 4),
		bitextract.New(serialStartBit-7, 7),
		bitextract.New(serialStartBit-10, 10),
		bitextract.New(serialStartBit-14, 14),
		bitextract.New(serialStartBit-17, 17),
		bitextract.New(serialStartBit-20, 20),
		bitextract.New(serialStartBit-24, 24),
	}

	// max number of item references that each partition allows = (10^partition)
	// note: partition 0 doesn't really allow any items, as the company prefix
	// takes the entire field. it can be thought of as a single item, though
	maxItems = [7]int{
		1,
		10,
		100,
		1000,
		10000,
		100000,
		1000000,
	}

	// max value for company prefix each partition allows
	// note: many are forbidden by GS1 rules
	maxPrefix = [7]int{
		999999999999,
		99999999999,
		9999999999,
		999999999,
		99999999,
		9999999,
		999999,
	}
)

// DecodeSGTIN decodes SGTIN-96 and SGTIN-198 encoded EPCs to SGTIN structures,
// or returns an error if the data isn't valid.
//
// For SGTIN-198, the data's leading bit should be the first bit of the first
// byte, and the final byte should be padded with two trailing 0s, since 198
// bits is not otherwise byte-aligned.
func DecodeSGTIN(b []byte) (SGTIN, error) {
	if len(b) == 0 {
		return SGTIN{}, errors.New("no data provided")
	}

	var serial string
	switch b[0] {
	case SGTIN96Header:
		if len(b) != SGTIN96NumBytes {
			return SGTIN{}, errors.Errorf("SGTIN-96 should have %d bytes", SGTIN96NumBytes)
		}
		serial = fmt.Sprintf("%d", int(serial96Ext.ExtractUInt64(b)))
	case SGTIN198Header:
		if len(b) != SGTIN198NumBytes {
			return SGTIN{}, errors.Errorf("SGTIN-198 should have %d bytes", SGTIN198NumBytes)
		}
		serial = fmt.Sprintf("%d", serial198Ext.Extract(b))
	default:
		return SGTIN{}, errors.Errorf("not an SGTIN header: %#X", b[0])
	}
	filter := FilterValue(filterExt.ExtractUInt64(b))
	if filter > 7 {
		return SGTIN{}, errors.Errorf("invalid filter: %d", filter)
	}
	partition := int(partitionExt.ExtractUInt64(b))
	if partition > 6 {
		return SGTIN{}, errors.Errorf("invalid partition: %d", partition)
	}

	companyPrefix := int(companyExt[partition].ExtractUInt64(b))
	iir := int(iirExt[partition].ExtractUInt64(b))

	// split indicator & item ref
	indicator := iir / maxItems[partition]
	itemRef := 0
	if partition > 0 {
		itemRef = iir - (indicator * maxItems[partition] * 10)
	}

	return SGTIN{
		filter:        filter,
		partition:     partition,
		companyPrefix: companyPrefix,
		indicator:     indicator,
		itemRef:       itemRef,
		serial:        serial,
	}, nil
}

type FilterValue int

const (
	Other     = FilterValue(0)
	POS       = FilterValue(1)
	FullCase  = FilterValue(2)
	reserved1 = FilterValue(3)
	InnerPack = FilterValue(4)
	reserved2 = FilterValue(5)
	UnitLoad  = FilterValue(6)
	UnitPack  = FilterValue(7)
)

// IsValid returns false if the FilterValue is outside the available range of
// filter values, or if it equals one of the GS1 reserved filter values; other-
// wise it returns true.
func (fv FilterValue) IsValid() bool {
	return fv >= Other && fv <= UnitPack &&
		!(fv == reserved1 || fv == reserved2)
}

func (fv FilterValue) String() string {
	switch fv {
	case Other:
		return "Other"
	case POS:
		return "POS"
	case FullCase:
		return "Full Case"
	case InnerPack:
		return "Inner Pack"
	case UnitLoad:
		return "Unit Load"
	case UnitPack:
		return "Unit Pack"
	case 3, 5:
		return "Reserved"
	}
	return "Unknown filter value: " + strconv.Itoa(int(fv))
}

/* Apache v2 license
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package epc

import (
	"encoding/hex"
	"fmt"
	"github.com/intel/rsp-sw-toolkit-im-suite-tagcode/bitextract"
	"github.com/pkg/errors"
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

func (s *SGTIN) Serial() string {
	return s.serial
}

func (s *SGTIN) Filter() FilterValue {
	return s.filter
}

func (s *SGTIN) Partition() int {
	return s.partition
}

func (s *SGTIN) CompanyPrefix() string {
	return fmt.Sprintf("%0[1]*d", 12-s.partition, s.companyPrefix)
}

func (s *SGTIN) ItemReference() string {
	return fmt.Sprintf("%0[1]*d", s.partition, s.itemRef)
}

// NewSGTIN returns an SGTIN with the given values. If the parameters are
// inconsistent with the SGTIN standard, error is non-nil, but this still
// returns the inconsistent SGTIN. The validation methods on such an SGTIN will
// fail, but the URI and GTIN methods will still attempt to return a value.
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
//
// The SGTIN's values ARE validated using ValidateRanges, and this if they are
// invalid, this function returns that error.
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
//
// The SGTIN's values ARE validated using ValidateRanges, and this if they are
// invalid, this function returns that error.
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
func (s SGTIN) ValidateRanges() error {
	if s.indicator < 0 || s.indicator > 9 {
		return errors.Errorf("indicator must be in [0,9], but is %d", s.indicator)
	}
	if !s.filter.IsValid() {
		return errors.Errorf("filter must be in {0, 1, 3, 4, 6, 7, 8, 9}, "+
			"but this is: %d", s.filter)
	}
	if s.partition < 0 || s.partition > 6 {
		return errors.Errorf("partition must be in [0,6], but is %d", s.partition)
	}
	if s.itemRef < 0 || s.itemRef > maxItems[s.partition]-1 {
		return errors.Errorf("item refs in partition %d must be in [0, %d], "+
			"but is %d", s.partition, maxItems[s.partition]-1, s.itemRef)
	}
	if s.companyPrefix < 0 || s.companyPrefix > maxPrefix[s.partition] {
		return errors.Errorf("company prefix in partition %d must be in [0, %d], "+
			"but is %d", s.partition, maxPrefix[s.partition], s.companyPrefix)
	}
	if s.serial == "" {
		return errors.New("serial is empty")
	}
	if len(s.serial) > 20 {
		return errors.Errorf("SGTIN serial numbers are limited to at most "+
			"20 characters, but this serial has %d characters", len(s.serial))
	}
	if !IsGS1AIEncodable(s.serial) {
		return errors.Errorf("SGTIN serial numbers may only contain ASCII "+
			"characters in the GS1 AI Encodable Character Set 82 and trailing "+
			"null bytes, but this serial is %q, which has illegal characters or"+
			"characters following null.",
			s.serial)
	}
	return nil
}

// CanSGTIN96 returns true if the SGTIN's serial may be encoded as SGTIN-96.
//
// The EPC Tag Data Standard specifies that SGTIN-96 encoded serial numbers must
// consist only of decimal values (0-9) less than 2^(38), with no leading '0's,
// except for a single '0'.
func (s SGTIN) CanSGTIN96() error {
	if s.serial == "" {
		return errors.New("serial is empty")
	}
	_, err := strconv.ParseUint(s.serial, 10, 38)
	if err != nil {
		return errors.Wrap(err, "SGTIN96 serial numbers must be numeric")
	}
	if s.serial[0] == '0' && s.serial != "0" {
		return errors.New("serials cannot have leading '0's, " +
			"except for the unique value '0'")
	}
	return nil
}

// GTIN returns the GS1 GTIN element string represented by this SGTIN.
func (s SGTIN) GTIN() string {
	if s.partition == 0 {
		// no item reference
		return fmt.Sprintf("%d%012d%d",
			s.indicator,
			s.companyPrefix,
			s.checkDigit())
	}
	return fmt.Sprintf("%d%0[2]*d%0[4]*d%d",
		s.indicator,
		12-s.partition, s.companyPrefix,
		s.partition, s.itemRef,
		s.checkDigit())
}

// URI returns the EPC Pure Identity URI for this SGTIN, of the format:
//     urn:epc:id:sgtin:CompanyPrefix.ItemRefAndIndicator.SerialNumber
// The serial number is escaped, if necessary, to conform with GS1 specs, but
// it is not validated.
func (s SGTIN) URI() string {
	if s.partition == 0 {
		// no item reference; just indicator
		return fmt.Sprintf("%s:%0[2]*d.%d.%s",
			SGTINPureURIPrefix,
			12-s.partition, s.companyPrefix,
			s.indicator,
			gs1Escaper.Replace(s.serial))
	}
	return fmt.Sprintf("%s:%0[2]*d.%d%0[5]*d.%s",
		SGTINPureURIPrefix,
		12-s.partition, s.companyPrefix,
		s.indicator, s.partition, s.itemRef,
		gs1Escaper.Replace(s.serial))
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
func (s SGTIN) checkDigit() int {
	sum := checkSum(s.itemRef, 1) +
		checkSum(s.companyPrefix, 13-s.partition) +
		checkSum(s.indicator, 13)

	// mod 10 additive inverse
	return (10 - (sum % 10)) % 10
}

const (
	headerLen    = 8
	filterLen    = 3
	partitionLen = 3
	prefixIIRLen = 44
	serial96Len  = 96 - serialStartBit
	serial198Len = 198 - serialStartBit

	headerStartBit    = 0
	filterStartBit    = headerStartBit + headerLen
	partitionStartBit = filterStartBit + filterLen
	gcpStartBit       = partitionStartBit + partitionLen
	serialStartBit    = gcpStartBit + prefixIIRLen

	serialStartByte = serialStartBit / 8
	serialOffsetBit = serialStartBit % 8
)

var (
	filterExt    = bitextract.New(filterStartBit, filterLen)
	partitionExt = bitextract.New(partitionStartBit, partitionLen)
	serial96Ext  = bitextract.New(serialStartBit, serial96Len)

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
// or returns an error if the data cannot be converted to an SGTIN.
//
// If err is nil, it merely means the data's _could_ be split into SGTIN pieces,
// but not that it represents a valid SGTIN. This function only returns an error
// on empty input, unknown headers, invalid lengths for the format, and invalid
// partition values (its value is necessary to split other fields). It does not
// otherwise validate that the values fall within the range of acceptable, non-
// reserved, encodeable values as defined by the EPC Tag Data Standard.
//
// Use ValidateRanges to check the values are within the EPC ranges.
//
// This function evaluates the MSB of the first byte as the MSB of the EPC data.
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
			return SGTIN{}, errors.Errorf("SGTIN-96 should have %d bytes, "+
				"but this has %d bytes", SGTIN96NumBytes, len(b))
		}
		serial = fmt.Sprintf("%d", int(serial96Ext.ExtractUInt64(b)))
	case SGTIN198Header:
		if len(b) != SGTIN198NumBytes {
			return SGTIN{}, errors.Errorf("SGTIN-198 should have %d bytes, "+
				"but this has %d bytes", SGTIN198NumBytes, len(b))
		}
		// SGTIN-198 serials are 20, 7-bit ISO 646 values
		s, n, charAfterNull := DecodeASCIIAt(b[serialStartByte:], serialOffsetBit)
		if charAfterNull {
			serial = s // technically, invalid, but available for validation
		} else {
			serial = s[:n] // null terminated
		}
	default:
		return SGTIN{}, errors.Errorf("SGTIN headers are 0x30 and 0x36, "+
			"but this is: %#X", b[0])
	}

	filter := FilterValue(filterExt.ExtractUInt64(b))

	// most values we can safely validate later, but if the partition isn't
	// valid, we don't know how to split the other values.
	partition := int(partitionExt.ExtractUInt64(b))
	if partition < 0 || partition > 6 {
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

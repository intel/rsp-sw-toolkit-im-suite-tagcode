package tagcode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"github.impcloud.net/RSP-Inventory-Suite/tagcode/bitextract"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// referenceYear is used to parse tag URI authority dates.
const referenceYear = "2006-01-02"

// authorityRegex is based on RFC-1035 and RFC-3986#3.2 and used to check the authority string.
var authorityRegex = regexp.MustCompile(`^[a-z](\.[-a-z0-9]{1,63}|[-a-z0-9]{1,63})*$`)

// fieldsRegex is used to validate that fields are non-empty, numeric entries
var fieldsRegex = regexp.MustCompile(`^\d(\d*)$`)

// BitTagDecoder extracts data from tag data based on fixed, adjacent bit widths.
type BitTagDecoder struct {
	// RFC-4151: "tag:" + authorityName + "," + date
	uriPrefix string
	bitextract.BitExploder
}

// NewBitTagDecoder returns a new BitTagDecoder.
func NewBitTagDecoder(authority, date string, widths []int) (BitTagDecoder, error) {
	btd := BitTagDecoder{}
	if err := btd.setTaggingEntity(authority, date); err != nil {
		return btd, err
	}

	d, err := bitextract.NewBitExploder(widths)
	if err != nil {
		return btd, err
	}
	btd.BitExploder = d

	return btd, nil
}

// BitTag is a tag represented as a series of numeric string fields.
type BitTag struct {
	uriPrefix string
	fields    []interface{} // empty interface to handle different number types
}

// URI returns a URI unique to this BitTag's prefix and fields.
//
// This uri scheme is derived from the Tag URI defined by www.taguri.org and
// published as RFC 4151. The syntax of the URI, in ABNF, is:
// tagURI = "tag:" taggingEntity ":" specific [ "#" fragment ]
// taggingEntity = authorityName "," date
// authorityName = DNSname / emailAddress
// date = year ["-" month ["-" day]]
// specific = BitTag's fields encoded as "." separated list of base-10 values
func (bt BitTag) URI() string {
	return fmt.Sprintf("%s:%s", bt.uriPrefix, bt)
}

// NumFields returns the number of fields this BitTag has.
func (bt BitTag) NumFields() int {
	return len(bt.fields)
}

// FormatField returns a field of the BitTag formatted with the given format.
//
// It'll panic if the index is outside the number of fields.
func (bt BitTag) FormatField(format string, idx int) string {
	return fmt.Sprintf(format, bt.fields[idx])
}

// HexField returns the idx field as upper-case hex characters, zero-padded to
// the given length.
func (bt BitTag) HexField(idx, length int) string {
	return fmt.Sprintf("%0[1]*X", length, bt.fields[idx])
}

// String formats the BitTag as a series of "." separated base-10 values.
func (bt BitTag) String() string {
	if len(bt.fields) == 0 {
		return ""
	}
	b := &strings.Builder{}
	for i := 0; i < len(bt.fields)-1; i++ {
		fmt.Fprintf(b, "%d.", bt.fields[i])
	}
	fmt.Fprintf(b, "%d", bt.fields[len(bt.fields)-1])
	return b.String()
}

// DecodeString is a convenience method that decodes hex-encoded byte data.
func (btd *BitTagDecoder) DecodeString(data string) (bt BitTag, err error) {
	byteData, err := hex.DecodeString(data)
	if err != nil {
		err = errors.Wrapf(err, "unable to decode tag data as hex")
		return
	}
	return btd.Decode(byteData)
}

// Decode uses this decoder to decode tag data from a byte slice.
func (btd BitTagDecoder) Decode(data []byte) (bt BitTag, err error) {
	if len(data)*8 < btd.BitLength() {
		err = errors.Errorf("invalid data length %d; expected %d bits",
			len(data)*8, btd.BitLength())
		return
	}

	fields, err := btd.Explode(data)
	if err != nil {
		return
	}

	bt.uriPrefix = btd.uriPrefix
	bt.fields = make([]interface{}, btd.NumFields())
	buff := make([]byte, 8)
	for fieldIdx, field := range fields {
		if len(field) <= 8 {
			binary.BigEndian.PutUint64(buff, 0)
			copy(buff[8-len(field):], field)
			bt.fields[fieldIdx] = binary.BigEndian.Uint64(buff)
		} else {
			bigInt := big.NewInt(0)
			bigInt.SetBytes(field)
			bt.fields[fieldIdx] = bigInt
		}
	}

	return
}

// Fields returns the URI's fields or an error if the URI is not valid.
//
// The URI is valid if it's prefix matches the decoder's prefix, it has the same
// number of fields as the decoder, those fields consist only of digits 0-9.
func (btd BitTagDecoder) Fields(uri string) ([]string, error) {
	if !strings.HasPrefix(uri, btd.uriPrefix+":") {
		return nil, errors.Errorf("prefix should be '%s'",
			btd.uriPrefix)
	}

	fields := strings.SplitN(uri[(len(btd.uriPrefix)+1):], ".", btd.NumFields())
	if len(fields) < btd.NumFields() {
		return nil, errors.Errorf("missing %d fields", btd.NumFields()-len(fields))
	}

	for i := range fields {
		if !fieldsRegex.MatchString(fields[i]) {
			return nil, errors.Errorf("field %d is invalid (it's empty "+
				"or contains non-numeric characters)", i)
		}
	}

	return fields, nil
}

// Field returns a specific field of the URI or an error if the URI is not valid.
//
// Note that this method validates the entire URI - if you're using the field
// more than once, it's most efficient to extract it once with this method, save
// it, and use it as needed.
func (btd BitTagDecoder) Field(URI string, idx int) (string, error) {
	fields, err := btd.Fields(URI)
	if err != nil {
		return "", err
	}
	if idx > len(fields) {
		return "", errors.Errorf("not enough fields to get index %d", idx)
	}
	return fields[idx], nil
}

func (btd *BitTagDecoder) setTaggingEntity(authority string, date string) error {
	if authority == "" {
		return errors.New("missing tagging entity authority")
	}
	if date == "" {
		return errors.New("missing tagging entity date")
	}

	// Although we could silently "fix" some problems for the user, it would
	// likely lead to more confusion, so instead, reject it bad config values.
	if len(authority) > 255 || !authorityRegex.MatchString(authority) {
		return errors.Errorf("bad authority '%s': "+
			"authority must be a fully-qualified domain name, "+
			"using only lower-case a-z, digits 0-9, periods ('.') and hyphens ('-'), "+
			"fewer than 255 total characters, with individual parts "+
			"(separated by '.') containing 63 characters or fewer.", authority)
	}

	if _, err := time.Parse(referenceYear, date); err != nil {
		return errors.Wrapf(err, "invalid authority date")
	}

	btd.uriPrefix = fmt.Sprintf("tag:%s,%s", authority, date)
	return nil
}

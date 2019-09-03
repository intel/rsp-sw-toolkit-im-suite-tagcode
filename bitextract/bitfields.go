package bitextract

import (
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"strconv"
	"strings"
)

// BitExploder explodes a single byte into a series of byte slices by breaking it
// into byte slices of predefined bit widths.
type BitExploder struct {
	bitLength  int // sum of all bit lengths
	expByteLen int // sum of all extractor byte lengths
	extractors []BitExtractor
}

// NewBitExploder returns a new BitExploder that explodes byte data into a series
// of consecutive byte slices according to the given widths.
func NewBitExploder(widths []int) (BitExploder, error) {
	btd := BitExploder{}

	if err := btd.SetWidths(widths); err != nil {
		return btd, err
	}

	return btd, nil
}

// DecodeString is a convenience method that decodes hex-encoded byte data using
// this decoder.
func (exp *BitExploder) DecodeString(data string) (bt [][]byte, err error) {
	byteData, err := hex.DecodeString(data)
	if err != nil {
		err = errors.Wrapf(err, "unable to decode tag data as hex")
		return
	}
	return exp.Explode(byteData)
}

// Explode uses this decoder to explode data from a byte slice, returning a
// slice of byte slices, each one representing a consecutive field consisting of
// bits extracted from a portion of the data slice.
func (exp BitExploder) Explode(data []byte) ([][]byte, error) {
	if len(data)*8 < exp.bitLength {
		return nil, errors.Errorf("invalid data length %d; expected %d bits",
			len(data)*8, exp.bitLength)
	}

	bt := exp.Buffer()
	exp.ExplodeTo(bt, data)
	return bt, nil
}

// ExplodeTo explodes the data into the dst byte slices.
//
// If there aren't enough destination slices, or any of the destination slices
// are too small for their respective fields, ExtractTo will panic.
func (exp BitExploder) ExplodeTo(dst [][]byte, data []byte) {
	if len(dst) < len(exp.extractors) {
		panic(fmt.Sprintf("not enough destination slices (%d) to "+
			"extract %d fields", len(dst), len(exp.extractors)))
	}
	for idx, be := range exp.extractors {
		// panics if len(dst[idx]) < be.ByteLength()
		be.ExtractTo(dst[idx], data)
	}
}

// ExplodedByteLength returns the minimum number of bytes necessary to store the
// exploded bit fields.
//
// This number is very likely larger than the number of bytes needed to store
// the unexploded bit fields; the exception to this is the case when each bit
// field is byte aligned -- i.e., has a length equal to a multiple of 8.
func (exp BitExploder) ExplodedByteLength() int {
	return exp.expByteLen
}

// BitReader uses a BitExploder to return consecutive fields from an underlying
// data byte slice.
type BitReader struct {
	exp   BitExploder
	field int
	data  []byte
}

// NewBitReader creates a new BitReader around a data slice using the BitExploder.
func (exp BitExploder) NewBitReader(data []byte) (*BitReader, error) {
	br := &BitReader{exp: exp}
	return br, br.SetData(data)
}

// Reset resets the reader so that future calls to its Read methods start at
// field 0.
func (r *BitReader) Reset() {
	r.field = 0
}

// SetData changes the reader's underlying data slice, resetting it in the process.
func (r *BitReader) SetData(data []byte) error {
	if len(data)*8 < r.exp.bitLength {
		return errors.Errorf("not enough bytes: this exploder needs "+
			"at least %d bytes, but data has only %d", r.exp.expByteLen, len(data))
	}
	r.data = data
	r.field = 0
	return nil
}

// Read extracts reader's current field's bit from the underlying data buffer,
// puts them into p, and advances the field index so that the next read returns
// bits from the next field.
//
// This method returns len(p), nil on success, regardless of the current field size.
// If p is too small for the number of bytes needed by this field, this returns
// 0, io.ErrShortBuffer and does not advance the reader's field. After all fields
// have been, subsequent calls to Read return 0, io.EOF. Use SetData or Reset to
// make use of this reader again.
func (r *BitReader) Read(p []byte) (int, error) {
	if r.field >= r.exp.NumFields() {
		return 0, io.EOF
	}
	ex := r.exp.extractors[r.field]
	if ex.dstLen > len(p) {
		return 0, io.ErrShortBuffer
	}
	// clear initial bytes
	for i := 0; i < len(p)-ex.dstLen; i++ {
		p[i] = 0
	}
	ex.ExtractTo(p[len(p)-ex.dstLen:], r.data)
	r.field++
	return len(p), nil
}

// Buffer returns a slice of byte slices large enough to use with ExtractTo.
//
// That is, the returned slice has the same number of buffers as the BitExploder
// has fields, and each of those slices are large enough to hold the number of
// destination byte of the individual BitExtractors.
func (exp BitExploder) Buffer() [][]byte {
	bigBuff := make([]byte, exp.expByteLen)
	bt := make([][]byte, len(exp.extractors))
	for idx, be := range exp.extractors {
		bt[idx] = bigBuff[:be.ByteLength()]
		bigBuff = bigBuff[be.ByteLength():]
	}
	return bt
}

// NumFields returns the number of fields this decoder has.
func (exp BitExploder) NumFields() int {
	return len(exp.extractors)
}

// SplitWidths is a helper function for validating and converting a slice of bit
// widths from a configuration string delimited by a particular delimiter.
//
// It splits the string on the delimiter, trims spaces around entries, converts
// the elements into ints, and returns the result. The purpose of this function
// is to allow calls like:
//     w, err := SplitWidths("8.44.44")
//     if err != nil {
//         return err
//     }
//     NewBitDecoder(w)
func SplitWidths(conf, delim string) ([]int, error) {
	var r []int
	for i, wStr := range strings.Split(conf, delim) {
		wStr = strings.TrimSpace(wStr)
		if wStr == "" {
			return nil, errors.Errorf("width %d is empty", i)
		}
		w, err := strconv.Atoi(wStr)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to convert width %d", i)
		}
		r = append(r, w)
	}
	return r, nil
}

// SetWidths sets the decoder's expected bit widths specification.
func (exp *BitExploder) SetWidths(widths []int) error {
	if len(widths) == 0 {
		return errors.New("widths slice is empty")
	}

	exp.bitLength = 0
	exp.extractors = make([]BitExtractor, len(widths))
	for i, w := range widths {
		if w <= 0 {
			return errors.Errorf("widths must be >0, but width %d is %d", i, w)
		}
		be := New(exp.bitLength, w)
		exp.extractors[i] = be
		exp.bitLength += w
		exp.expByteLen += be.ByteLength()
	}
	return nil
}

func (exp BitExploder) BitLength() int {
	return exp.bitLength
}

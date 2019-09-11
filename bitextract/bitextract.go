package bitextract

import (
	"encoding/binary"
	"fmt"
	"sync"
)

type alignmentBias uint8

const (
	ByteSize = 8
	ByteMask = (1 << ByteSize) - 1

	srcAligned = alignmentBias(iota)
	srcBiasPrev
	srcBiasNext
)

// BitExtractor extracts bits from byte slices according to bit offsets into the
// slice and the lengths of the section to be extracted.
//
// Create a new one with NewBitExtractor(start, length), then use Extract(src)
// or ExtractTo(dst, src) to extract bits from byte slices.
//
// BitExtractors are safe for concurrent extractions, provided callers don't use
// SetBounds during their use.
type BitExtractor struct {
	bitStart, byteStart, srcLen, dstLen int
	bias                                alignmentBias
	rshift, lshift, mask                uint8
}

// ByteLength returns the number of bytes this extractor extracts.
//
// That is, the result of len(be.Extract(data)) == be.ByteLength().
func (be BitExtractor) ByteLength() int {
	return be.dstLen
}

// Buffer returns a buffer of the size needed by ExtractTo.
func (be BitExtractor) Buffer() []byte {
	return make([]byte, be.ByteLength())
}

// New returns a new BitExtractor that can extract bits from a bytes.
//
// start is the 0-index of the first bit of the input. Bit 0 is the highest-
// order bit of the 0'th index of the input array. len is the number of bits to
// extract, starting from that start bit and moving "rightward" through the slice,
// so that later bits are extracted from higher indexes.
func New(start, len int) (be BitExtractor) {
	be = BitExtractor{}
	be.SetBounds(start, len)
	return be
}

func ifAligned(size, ifYes, ifNo int) int {
	if size%ByteSize == 0 {
		return ifYes
	}
	return ifNo
}

// SetBounds changes the BitExtractor's start bit and bit length.
func (be *BitExtractor) SetBounds(start, len int) {
	if start < 0 || len < 1 {
		panic(fmt.Sprintf("illegal start (%d) or length (%d)", start, len))
	}
	if start+len < 0 {
		// check for overflow
		panic(fmt.Sprintf("cannot handle such a large start (%d) and length (%d)",
			start, len))
	}

	be.bitStart = start
	be.byteStart = start / ByteSize
	be.dstLen = len/ByteSize + ifAligned(len, 0, 1)
	srcEndByte := ((start + len) / ByteSize) - ifAligned(start+len, 1, 0)
	be.srcLen = srcEndByte - be.byteStart + 1
	srcEndOffset := (start + len - 1) % ByteSize
	be.rshift = uint8(ByteSize - srcEndOffset - 1)
	be.lshift = uint8(srcEndOffset + 1)
	be.mask = byte(ifAligned(len, ByteMask, (1<<uint(len%ByteSize))-1))

	switch {
	case be.rshift == 0:
		be.bias = srcAligned
	case be.srcLen == be.dstLen:
		be.bias = srcBiasPrev
	default:
		be.bias = srcBiasNext
	}

	return
}

// bufferPool maintains a pool of reusable byte slices.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 8)
	},
}

// Extracts bits from the source and interprets them as a BigEndian uint64.
// This method panics if the extractor's ByteLength is greater than 8.
func (be BitExtractor) ExtractUInt64(src []byte) uint64 {
	buff := bufferPool.Get().([]byte)
	defer bufferPool.Put(buff)
	binary.BigEndian.PutUint64(buff, 0)
	be.ExtractTo(buff[8-be.dstLen:], src)
	return binary.BigEndian.Uint64(buff)
}

func (be BitExtractor) Extract(src []byte) []byte {
	dest := be.Buffer()
	be.ExtractTo(dest, src)
	return dest
}

func (be BitExtractor) ExtractTo(dest, src []byte) {
	if len(src) < be.srcLen+be.byteStart {
		panic(fmt.Sprintf("cannot extract %d bytes from source[%d:%d], "+
			"as it only has %d total bytes",
			be.srcLen, be.byteStart, be.byteStart+be.srcLen, len(src)))
	}

	if len(dest) < be.dstLen {
		panic(fmt.Sprintf("destination size %d is too small "+
			"(should be at least %d)", len(dest), be.dstLen))
	}

	switch be.bias {
	case srcAligned:
		copy(dest, src[be.byteStart:be.byteStart+be.dstLen])
	case srcBiasPrev:
		dest[0] = src[be.byteStart] >> be.rshift
		for i := 1; i < be.dstLen; i++ {
			// previous byte shifts up; current byte shifts down
			dest[i] = src[i+be.byteStart-1]<<(ByteSize-be.rshift) |
				src[i+be.byteStart]>>be.rshift
		}
	case srcBiasNext:
		for i := 0; i < be.dstLen; i++ {
			// current byte shifts up; next byte shifts down
			dest[i] = src[i+be.byteStart]<<(ByteSize-be.rshift) |
				src[i+be.byteStart+1]>>be.rshift
		}
	}
	dest[0] &= be.mask
}

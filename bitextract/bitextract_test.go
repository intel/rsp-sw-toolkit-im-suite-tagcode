package bitextract

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.impcloud.net/RSP-Inventory-Suite/expect"
	"math/big"
	"math/rand"
	"testing"
)

func TestBitExtractor(t *testing.T) {
	w := expect.WrapT(t)

	be := New(0, 8)
	w.ShouldBeEqual(be.bitStart, 0)
	w.ShouldBeEqual(be.dstLen, 1)
	w.ShouldBeEqual(be.byteStart, 0)
	w.ShouldBeEqual(be.rshift, uint8(0))
	w.ShouldBeEqual(be.lshift, uint8(8))

	be = New(0, 2)
	w.ShouldBeEqual(be.bitStart, 0)
	w.ShouldBeEqual(be.dstLen, 1)
	w.ShouldBeEqual(be.byteStart, 0)
	w.ShouldBeEqual(be.rshift, uint8(6))
	w.ShouldBeEqual(be.lshift, uint8(2))

	be = New(0, 10)
	w.ShouldBeEqual(be.bitStart, 0)
	w.ShouldBeEqual(be.dstLen, 2)
	w.ShouldBeEqual(be.byteStart, 0)
	w.ShouldBeEqual(be.rshift, uint8(6))
	w.ShouldBeEqual(be.lshift, uint8(2))

	be = New(3, 10)
	w.ShouldBeEqual(be.bitStart, 3)
	w.ShouldBeEqual(be.dstLen, 2)
	w.ShouldBeEqual(be.byteStart, 0)
	w.ShouldBeEqual(be.rshift, uint8(3))
	w.ShouldBeEqual(be.lshift, uint8(5))
	w.ShouldBeEqual(be.mask, uint8(0x03))

	be = New(3, 18)
	w.ShouldBeEqual(be.bitStart, 3)
	w.ShouldBeEqual(be.dstLen, 3)
	w.ShouldBeEqual(be.byteStart, 0)
	w.ShouldBeEqual(be.rshift, uint8(3))
	w.ShouldBeEqual(be.lshift, uint8(5))
	w.ShouldBeEqual(be.mask, uint8(0x03))

	be = New(4, 4)
	w.ShouldBeEqual(be.bitStart, 4)
	w.ShouldBeEqual(be.dstLen, 1)
	w.ShouldBeEqual(be.byteStart, 0)
	w.ShouldBeEqual(be.rshift, uint8(0))
	w.ShouldBeEqual(be.lshift, uint8(8))
	w.ShouldBeEqual(be.mask, uint8(0x0F))

	be = New(4, 2)
	w.ShouldBeEqual(be.bitStart, 4)
	w.ShouldBeEqual(be.dstLen, 1)
	w.ShouldBeEqual(be.byteStart, 0)
	w.ShouldBeEqual(be.rshift, uint8(2))
	w.ShouldBeEqual(be.lshift, uint8(6))
	w.ShouldBeEqual(be.mask, uint8(0x03))
}

func TestBitExtractor_panic(t *testing.T) {
	assertPanics := func(f func()) {
		defer func() {
			recover()
		}()
		f()
		t.Fatal("expected function to panic, but it didn't")
	}

	assertPanics(func() { New(-1, 0) })
	assertPanics(func() { New(1, 0) })
	assertPanics(func() { New(1, -1) })
	assertPanics(func() { New(-1, 1) })
	assertPanics(func() { New(1<<63-1, 1<<63-1) })

	be := New(5, 9)
	holds2Bytes := make([]byte, 2)
	data, _ := hex.DecodeString("FCDF")

	assertPanics(func() { be.Extract(data[1:]) })
	assertPanics(func() { be.Extract(data[2:]) })
	assertPanics(func() { be.ExtractTo(holds2Bytes, data[1:]) })
	assertPanics(func() { be.ExtractTo(holds2Bytes, data[2:]) })
	assertPanics(func() { be.ExtractTo(holds2Bytes[1:], data) })
	assertPanics(func() { be.ExtractTo(holds2Bytes[2:], data) })
}

func TestProperties(t *testing.T) {
	w := expect.WrapT(t)

	// offsets always [0,7]
	for i := 0; i < 1000; i++ {
		start := rand.Int()
		length := (rand.Int() % ((1<<63 - 1) - start)) + 1
		w.ShouldBeTrue(start >= 0)
		w.ShouldBeTrue(length >= 1)

		be := New(start, length)
		w.ShouldBeTrue(be.dstLen > 0)
		w.ShouldBeTrue(be.rshift >= 0 && be.rshift <= 7)
		w.ShouldBeTrue(be.lshift >= 0 && be.rshift <= 7)
	}

	// increase length by 8 bits only affects final byte
	for i := 0; i < 1000; i++ {
		start := rand.Int()
		length := (rand.Int() % ((1<<63 - 2) - start)) + 1

		be := New(start, length)
		be2 := New(start, length+8)

		w.ShouldBeEqual(be.dstLen, be2.dstLen-1)
		w.ShouldBeEqual(be.byteStart, be2.byteStart)
		w.ShouldBeEqual(be.rshift, be2.rshift)
		w.ShouldBeEqual(be.lshift, be2.lshift)
		w.ShouldBeEqual(be.mask, be2.mask)
	}

	// increasing the offset by 8 should only affect the start position
	for i := 0; i < 1000; i++ {
		start := rand.Int()
		length := (rand.Int() % ((1<<63 - 2) - start)) + 1

		be := New(start, length)
		be2 := New(start+8, length)

		w.ShouldBeEqual(be.byteStart, be2.byteStart-1)
		w.ShouldBeEqual(be.dstLen, be2.dstLen)
		w.ShouldBeEqual(be.rshift, be2.rshift)
		w.ShouldBeEqual(be.lshift, be2.lshift)
		w.ShouldBeEqual(be.mask, be2.mask)
	}

	// increasing the offset by 1 should have predictable results
	for i := 0; i < 1000; i++ {
		start := rand.Int()
		length := (rand.Int() % ((1<<63 - 2) - start)) + 1

		be := New(start, length)
		be2 := New(start+1, length)

		w.ShouldBeTrue(be.byteStart >= be2.byteStart-1)
		w.ShouldBeTrue(be.byteStart <= be2.byteStart)
		w.ShouldBeEqual(be.dstLen, be2.dstLen)
		w.ShouldContain([]uint8{0, be2.rshift + 1}, be.rshift)
		w.ShouldContain([]uint8{8, be2.lshift - 1}, be.lshift)
	}
}

func TestBitExtractor_ExtractAligned(t *testing.T) {
	w := expect.WrapT(t)
	be := New(0, 16)

	for _, t := range []string{"00FF", "FF00", "FFFF", "0F0F"} {
		data, _ := hex.DecodeString(t)
		w.ShouldBeEqual(data, be.Extract(data))
	}

	for _, t := range []string{"00FF0F", "00FF0A", "00FF0ABC"} {
		data, _ := hex.DecodeString(t)
		w.ShouldBeEqual(be.Extract(data), []byte{0x0, 0xFF})
	}
}

func TestBitExtractor_Extract(t *testing.T) {
	w := expect.WrapT(t)

	data, _ := hex.DecodeString("00FF")

	be := New(0, 12)
	w.ShouldBeEqual(be.Extract(data), []byte{0x0, 0x0F})

	be = New(2, 12)
	w.ShouldBeEqual(be.Extract(data), []byte{0x0, 0x3F})

	be = New(5, 9)
	w.ShouldBeEqual(be.Extract(data), []byte{0x0, 0x3F})

	data, _ = hex.DecodeString("FCDF")
	be = New(5, 9)
	w.ShouldBeEqual(be.Extract(data), []byte{0x01, 0x37})

	be = New(5, 2)
	w.ShouldBeEqual(be.Extract(data), []byte{0x02})

	be = New(5, 1)
	w.ShouldBeEqual(be.Extract(data), []byte{0x01})

	be = New(11, 2)
	w.ShouldBeEqual(be.Extract(data), []byte{0x03})
}

// extractUsingBitString is an alternative implementation that converts the
// incoming data to one large bit string, uses string functions to cut it apart,
// then converts the resulting string back to a byte slice. It's much simpler,
// but far slower and more memory-demanding. Benchmarking shows the difference
// is roughly two orders of magnitude in speed and ~1KB/extraction:
//
// goos: windows
// goarch: amd64
// pkg: github.impcloud.net/RSP-Inventory-Suite/tagcode/bitbound
// BenchmarkBitExtractor_Extract-20            10000000    130 ns/op     48 B/op   1 allocs/op
// BenchmarkBitExtractor_ExtractTo-20          20000000    104 ns/op      0 B/op   0 allocs/op
// BenchmarkBitStringExtraction-20               500000   3856 ns/op   1072 B/op  10 allocs/op
// BenchmarkBitExtractor_Extract_random-20      5000000    263 ns/op     64 B/op   1 allocs/op
// BenchmarkBitExtractor_ExtractTo_random-20   10000000    230 ns/op      0 B/op   0 allocs/op
// BenchmarkBitStringExtraction_random-20        300000   4697 ns/op   1089 B/op  10 allocs/op
//
// Note that ExtractTo requires no allocations: it's provided a destination buffer,
// allowing it to directly write the result. While Extract requires one allocation
// per operation, that allocation is indeed the destination buffer for the result,
// the size of which it can calculate upfront. Using a BitString is indeed simple,
// but comes at a heavy conversion penalty.
func extractUsingBitString(src []byte, start, length int) []byte {
	bi := big.NewInt(0)
	bi.SetBytes(src)
	bitStr := fmt.Sprintf("%0[1]*b", len(src)*8, bi)

	extractFromStr := bitStr[start : start+length]
	if _, ok := bi.SetString(extractFromStr, 2); !ok {
		panic("unable to convert from binary to decimal")
	}
	return bi.Bytes()
}

func TestBitExtractor_CompareToString(t *testing.T) {
	w := expect.WrapT(t).StopOnMismatch()
	buff := make([]byte, 50)

	rand.Seed(3)
	for i := 0; i < 1000; i++ {
		rand.Read(buff)
		start := rand.Int() % ((len(buff) - 1) * 8)
		length := (rand.Int() % ((len(buff) * 8) - start)) + 1

		be := New(start, length)
		buff[be.byteStart] = 255

		fromBitExtractor := be.Extract(buff)

		fromBitString := extractUsingBitString(buff, start, length)

		w.As(fmt.Sprintf("%X %X", fromBitExtractor, fromBitString)).
			ShouldBeEqual(fromBitExtractor, fromBitString)
	}
}

func BenchmarkBitExtractor_Extract(b *testing.B) {
	start := 92
	length := 391 - 92
	buff, _ := hex.DecodeString("85FBE72B6064289004A531FF67898DF5319EE02992FD" +
		"D84021FA5052434BF6EE214B5FDF1409FC2B8A0A521C221BACB1BCA8")
	expected, _ := hex.DecodeString("0F67898DF5319EE02992FDD84021FA5052434BF6" +
		"EE214B5FDF1409FC2B8A0A521C221BACB1BC")

	be := New(start, length)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result := be.Extract(buff)
		if bytes.Equal(result, expected) {
			b.Errorf("result != expected: %X != %X", result, expected)
		}
	}
}

func BenchmarkBitExtractor_ExtractTo(b *testing.B) {
	start := 92
	length := 391 - 92
	buff, _ := hex.DecodeString("85FBE72B6064289004A531FF67898DF5319EE02992FD" +
		"D84021FA5052434BF6EE214B5FDF1409FC2B8A0A521C221BACB1BCA8")
	expected, _ := hex.DecodeString("0F67898DF5319EE02992FDD84021FA5052434BF6" +
		"EE214B5FDF1409FC2B8A0A521C221BACB1BC")

	be := New(start, length)
	result := make([]byte, be.ByteLength())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		be.ExtractTo(result, buff)
		if bytes.Equal(result, expected) {
			b.Errorf("result != expected: %X != %X", result, expected)
		}
	}
}

func BenchmarkBitStringExtraction(b *testing.B) {
	start := 92
	length := 391 - 92
	buff, _ := hex.DecodeString("85FBE72B6064289004A531FF67898DF5319EE02992FD" +
		"D84021FA5052434BF6EE214B5FDF1409FC2B8A0A521C221BACB1BCA8")
	expected, _ := hex.DecodeString("0F67898DF5319EE02992FDD84021FA5052434BF6" +
		"EE214B5FDF1409FC2B8A0A521C221BACB1BC")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := extractUsingBitString(buff, start, length)
		if bytes.Equal(result, expected) {
			b.Errorf("result != expected: %X != %X", result, expected)
		}
	}
}

func BenchmarkBitExtractor_Extract_random(b *testing.B) {
	buff := make([]byte, 50)
	be := New(0, 1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := 2
		length := (50 * 8) - 4

		rand.Read(buff)
		buff[start/8] = 255

		be.SetBounds(start, length)
		result := be.Extract(buff)
		if result[0] == 0 {
			b.Errorf("result[0] should always be > 0")
		}
	}
}

func BenchmarkBitExtractor_ExtractTo_random(b *testing.B) {
	buff := make([]byte, 50)
	resultBuff := make([]byte, 50)

	be := New(0, 1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := 2
		length := (50 * 8) - 4

		rand.Read(buff)
		buff[start/8] = 255

		be.SetBounds(start, length)
		be.ExtractTo(resultBuff[:be.ByteLength()], buff)
		if resultBuff[0] == 0 {
			b.Errorf("result[0] should always be > 0")
		}
	}
}

func BenchmarkBitStringExtraction_random(b *testing.B) {
	buff := make([]byte, 50)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := 2
		length := (50 * 8) - 4

		rand.Read(buff)
		buff[start/8] = 255

		result := extractUsingBitString(buff, start, length)
		if result[0] == 0 {
			b.Errorf("result[0] should always be > 0")
		}
	}
}

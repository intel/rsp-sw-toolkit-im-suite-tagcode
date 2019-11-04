/* Apache v2 license
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package bitextract

import (
	"encoding/binary"
	"encoding/hex"
	"github.com/intel/rsp-sw-toolkit-im-suite-expect"
	"io"
	"testing"
)

func TestBitExploder_Buffer(t *testing.T) {
	w := expect.WrapT(t)
	widths := []int{1, 8, 16, 2, 9, 17}
	byteLens := []int{1, 1, 2, 1, 2, 3}
	byteLenSum := 10

	btd := w.ShouldHaveResult(NewBitExploder(widths)).(BitExploder)
	w.StopOnMismatch().ShouldBeEqual(btd.ExplodedByteLength(), byteLenSum)
	buff := btd.Buffer()
	w.ShouldHaveLength(buff, len(widths))
	for i := 0; i < len(widths); i++ {
		w.ShouldHaveLength(buff[i], byteLens[i])
	}
}

func TestBitReader_Read(t *testing.T) {
	w := expect.WrapT(t)
	//        a    b         c              d   e           f              -
	// data: 0b1_10100110_1101100110111101_10_100100011_10001110111011110_000
	data := w.ShouldHaveResult(hex.DecodeString("d36cded238eef0")).([]byte)
	vals := []uint32{1, 166, 55741, 2, 291, 73182}
	widths := []int{1, 8, 16, 2, 9, 17}
	byteLenSum := 10

	exp := w.ShouldHaveResult(NewBitExploder(widths)).(BitExploder)
	w.StopOnMismatch().ShouldBeEqual(exp.ExplodedByteLength(), byteLenSum)

	r := w.ShouldHaveResult(exp.NewBitReader(data)).(*BitReader)
	buff := make([]byte, 4)
	for i := 0; i < len(widths); i++ {
		n := w.ShouldHaveResult(r.Read(buff)).(int)
		w.ShouldBeEqual(n, 4)
		v := binary.BigEndian.Uint32(buff)
		w.ShouldBeEqual(vals[i], v)
	}
	n, err := r.Read(buff)
	w.ShouldFail(err)
	w.ShouldBeEqual(err, io.EOF)
	w.ShouldBeEqual(n, 0)

	r.Reset()
	ints := make([]uint32, len(vals))
	for i := 0; i < len(widths); i++ {
		w.ShouldSucceed(binary.Read(r, binary.BigEndian, &ints[i]))
		w.ShouldBeEqual(vals[i], ints[i])
	}
	n, err = r.Read(buff)
	w.ShouldFail(err)
	w.ShouldBeEqual(err, io.EOF)
	w.ShouldBeEqual(n, 0)
}

func TestSplitWidths_invalidWidths(t *testing.T) {
	w := expect.WrapT(t)

	invalidWidths := []string{
		"8..40",
		"",
		".",
		"  ",
		"8.88.",
	}

	for _, widths := range invalidWidths {
		w.As(widths).ShouldHaveError(SplitWidths(widths, "."))
	}

	invalidWidths = []string{
		"8,,40",
		"",
		",",
		"  ",
		"8,88,",
	}

	for _, widths := range invalidWidths {
		w.As(widths).ShouldHaveError(SplitWidths(widths, ","))
	}
}

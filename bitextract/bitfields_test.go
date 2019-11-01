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

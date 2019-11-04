/* Apache v2 license
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package bittag

import (
	"github.com/intel/rsp-sw-toolkit-im-suite-expect"
	"testing"
)

func TestNewBitTagDecoder(t *testing.T) {
	w := expect.WrapT(t)

	decoder := w.ShouldHaveResult(NewDecoder(
		"test.com", "2019-01-01", []int{8, 48, 40})).(Decoder)

	bitTag, err := decoder.DecodeString("0F00000000000C00000014D2")
	w.As("decoding").ShouldSucceed(err)
	w.StopOnMismatch().ShouldBeEqual(len(bitTag.fields), 3)
	productID := bitTag.HexField(2, 4)
	w.As("productID").ShouldBeEqual(productID, "14D2")
	URI := bitTag.URI()
	w.As("URI").ShouldBeEqual(URI, "tag:test.com,2019-01-01:15.12.5330")
	decID := w.ShouldHaveResult(decoder.Field(URI, 2)).(string)
	w.As("productID from URI").ShouldBeEqual(decID, "5330")
}

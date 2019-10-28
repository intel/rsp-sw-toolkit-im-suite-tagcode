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

// Package epc implements several GS1 encoding and decoding schemes, particularly
// those referenced in the EPC Tag Data Standard. At present, this code should
// compliant with Release 1.12 (Ratified 2019 May).
//
// The following are links to the GS1 General Standard, EPC Tag Data Standard,
// and supplemental materials such as the "Interoperability of Barcodes, EPCIS,
// and RFID" PDF; this code is based on these guides and does its best to both
// follow its guidelines and properly implement its definitions. GS1 maintains
// several important documents and artifacts which should be considered when
// working within this space.
// - https://www.gs1.org/sites/default/files/docs/barcodes/GS1_General_Specifications.pdf
// - https://www.gs1.org/standards/epcrfid-epcis-id-keys/epc-rfid-tds/1-12
// - https://www.gs1.org/sites/default/files/docs/epc/GS1_EPC_TDS_i1_12.pdf
//
// Most significant in GS1's recommendations is the following idea:
//     "The canonical representation of an EPC is the pure-identity URI
//     	representation, which is intended for communicating and storing EPCs in
//     	information systems, databases and applications, in order to insulate
//     	them from knowledge about the physical nature of the tag, so that
//     	although 64 bit tags may differ from 96 bit tags in the choice of
//     	literal binary header values and the number of bits allocated to each
//     	element or field within the EPC, the pure-identity URI format does not
//     	require the information systems to know about these details; the pure-
//     	identity URI can be just a pure identifier."
//		- GS1 EPCglobal Tag Data Translation (TDT) 1.6
// In other words: convert tag data into a URI as soon as possible, and use that,
// because it's the least ambiguous, most contextual piece of information you
// could be using.
//
// EPC is confusing because first of all, an "Electronic Product Code" is not
// electronic, not just for products, and not a code. An EPC is an identifier
// assigned to exactly one "thing" (often, a product, but not always). It's can
// be encoded to several forms, and one of those forms is designed particularly
// for use with electronic tagging systems (i.e., RFID tags). But regardless of
// that, an EPC itself is not an RFID tag, not the item to which it is assigned,
// and not its binary or textual representation: it's just an ID of something.
// This has the very important implication that an EPC can be encoded into a few
// different formats (including multiple binary representations) and still be
// the same EPC -- as a result, the best way to ensure interoperability of the
// systems using EPCs, the best thing to do is gravitate towards an encoding
// that can unambiguously represent any EPC and yet still be useful with other
// identifiers that aren't EPCs: hence, the focus on URIs.
//
// There is, in fact, more than one URI representations of an EPC: one is the
// "Pure Identity" format, and it represents all the important information of
// the EPC without any specificity of how that EPC might or should be encoded.
// EPCs may also be encoded in a URI format designed to represent not only the
// important features of the EPC, but also details about a binary encoding for
// the EPC suitable for RFID tags. The problem, so to speak, with this second
// encoding is that an EPC may be encoded into multiple, different EPC Tag URIs:
//     "It is important to note that two EPCs are the same if and only if the
//     Pure Identity EPC URIs are character for character identical. A long
//     binary encoding (e.g., SGTIN-198) is not a different EPC from a short
//     binary encoding (e.g., SGTIN-96) if the GS1 Company Prefix, item
//     reference with indicator, and serial numbers are identical."
// 	   - GS1 EPC Tag Data Standard, p. 80
//
// Similarly, the same EPC may be encoded into multiple, different RFID tags
// (although per spec, all such tags identify the same physical object). In all
// such cases, there is no ambiguity of the EPC's details, but such versions
// complicate comparing one tag to another. For these reasons, we prefer using
// the Pure Identity URI in all cases _except_ those that require knowledge of
// the specific encoding format.
//
// A final complication occurs when considering that RFID tags may contain any
// information in their EPC field -- not necessarily a binary encoding of an EPC.
// In these cases, it is necessary that application logic distinguish the binary
// form before processing deeper in the application, as it is impossible in many
// cases to determine whether a particular set of 96 bits represents an EPC or
// some other data that happens to encode to an identical value. In these cases,
// converting the binary data into some canonical, unambiguous format ensures
// that the contextual information is carried with the data. If these cases
// adopt their own canonical URI format, then deeper application layers may
// freely treat all identifiers identically -- comparing URIs according to their
// RFC, without regard for variations on their possible encodings.
package epc

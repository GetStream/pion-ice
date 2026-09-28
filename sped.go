// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"encoding/binary"

	"github.com/pion/stun/v4"
)

// DtlsInStunAttribute is a STUN attribute for carrying DTLS embedded in STUN.
type DtlsInStunAttribute []byte

// AddTo adds DTLS-in-STUN attribute to message.
func (d DtlsInStunAttribute) AddTo(m *stun.Message) error {
	m.Add(stun.AttrDtlsInStun, d)

	return nil
}

// GetFrom decodes DTLS-in-STUN attribute from message.
func (d *DtlsInStunAttribute) GetFrom(m *stun.Message) error {
	v, err := m.Get(stun.AttrDtlsInStun)
	if err != nil {
		return err
	}

	*d = v

	return nil
}

// DtlsInStunAckAttribute is a STUN attribute for acknowledging the receipt
// of DTLS packets (embedded in STUN or without embedding).
type DtlsInStunAckAttribute []uint32

// ACKs are 32-bit values, and the attribute can carry up to four of them.
const (
	ackSizeValues = 4
	ackSizeBytes  = ackSizeValues * 4
)

// AddTo adds DTLS-in-STUN-ACK attribute to message.
func (a DtlsInStunAckAttribute) AddTo(m *stun.Message) error {
	if len(a) > ackSizeValues {
		return stun.ErrAttributeSizeInvalid
	}
	v := make([]byte, len(a)*4)
	for i, ack := range a {
		binary.BigEndian.PutUint32(v[i*4:], ack)
	}
	m.Add(stun.AttrDtlsInStunAck, v)

	return nil
}

// GetFrom decodes DTLS-in-STUN-ACK attribute from message.
func (a *DtlsInStunAckAttribute) GetFrom(m *stun.Message) error {
	v, err := m.Get(stun.AttrDtlsInStunAck)
	if err != nil {
		return err
	}
	if len(v) > ackSizeBytes || len(v)%4 != 0 {
		return stun.ErrAttributeSizeInvalid
	}
	u := make([]uint32, len(v)/4)
	for i := range u {
		u[i] = binary.BigEndian.Uint32(v[i*4 : (i+1)*4])
	}
	*a = DtlsInStunAckAttribute(u)

	return nil
}

// Sizes used by SPED (STUN Protocol for Embedding DTLS), following libwebrtc.
const (
	// MaxSTUNBindingBody is the largest STUN Binding body, in bytes, that SPED
	// attributes may grow a message to. It is 1200 bytes minus
	// MESSAGE-INTEGRITY (24) and FINGERPRINT (8), and does not count the
	// 20-byte STUN header. A DTLS datagram is embedded only if the body plus
	// the attribute header plus the datagram fits (libwebrtc
	// kMaxStunBindingLength).
	MaxSTUNBindingBody = 1200 - 24 - 8

	// SPEDDTLSMTU is the DTLS MTU recommended while SPED is enabled. libwebrtc
	// uses 900 so that a post-quantum ClientHello fits in two datagrams, each
	// of which fits in a Binding request.
	SPEDDTLSMTU = 900
)

const (
	// dtlsRecordHeaderLen is the size of a DTLS record header.
	dtlsRecordHeaderLen = 13
	// stunAttributeHeaderLen is the size of a STUN attribute header.
	stunAttributeHeaderLen = 4
)

// isDTLSPacket reports whether payload looks like a DTLS datagram
// (RFC 9443: first byte in 20..63), as libwebrtc IsDtlsPacket does.
func isDTLSPacket(payload []byte) bool {
	return len(payload) >= dtlsRecordHeaderLen && payload[0] > 19 && payload[0] < 64
}

// spedAttributes are the SPED attributes read from a received STUN message.
type spedAttributes struct {
	data    []byte
	hasData bool
	// acks is the decoded ACK list. It is only set when ackValid is true.
	acks []uint32
	// hasAck is true when an ACK attribute is present, even a malformed one.
	hasAck bool
	// ackValid is true when the ACK attribute length is a multiple of 4.
	ackValid bool
}

// spedAttributesFrom returns the first DTLS-in-STUN and DTLS-in-STUN-ACK
// attributes of m that precede MESSAGE-INTEGRITY. Attributes after
// MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256 or FINGERPRINT are not covered
// by the integrity check and are ignored.
//
// As in libwebrtc, an ACK whose length is not a multiple of 4 is reported as
// present but invalid, and an ACK longer than four entries is accepted.
func spedAttributesFrom(m *stun.Message) spedAttributes {
	var attrs spedAttributes
	for _, attr := range m.Attributes {
		switch attr.Type {
		case stun.AttrMessageIntegrity, stun.AttrMessageIntegritySHA256, stun.AttrFingerprint:
			return attrs
		case stun.AttrDtlsInStun:
			if !attrs.hasData {
				attrs.data = attr.Value
				attrs.hasData = true
			}
		case stun.AttrDtlsInStunAck:
			if !attrs.hasAck {
				attrs.hasAck = true
				attrs.acks, attrs.ackValid = decodeSPEDAcks(attr.Value)
			}
		default:
		}
	}

	return attrs
}

// decodeSPEDAcks decodes an ACK attribute value into big-endian CRC-32 values.
func decodeSPEDAcks(value []byte) ([]uint32, bool) {
	if len(value)%4 != 0 {
		return nil, false
	}
	acks := make([]uint32, len(value)/4)
	for i := range acks {
		acks[i] = binary.BigEndian.Uint32(value[i*4:])
	}

	return acks, true
}

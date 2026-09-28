// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"bytes"
	"hash/crc32"
	"slices"
)

// SPEDState is the state of SPED (STUN Protocol for Embedding DTLS) on an
// Agent. The states after SPEDStateDisabled are those of libwebrtc's
// DtlsStunPiggybackController.
type SPEDState int32

const (
	// SPEDStateDisabled means SPED was never enabled. The agent neither sends
	// nor reads SPED attributes.
	SPEDStateDisabled SPEDState = iota
	// SPEDStateTentative means SPED is enabled and no authenticated message has
	// been received from the peer yet.
	SPEDStateTentative
	// SPEDStateConfirmed means the peer sent at least one SPED attribute.
	SPEDStateConfirmed
	// SPEDStatePending means the local DTLS handshake is complete and the peer
	// has not yet acknowledged every datagram of the last flight.
	SPEDStatePending
	// SPEDStateComplete means SPED finished: the peer acknowledged the last
	// flight or application data arrived. No SPED attribute is sent or read.
	SPEDStateComplete
	// SPEDStateOff means SPED is not used: the peer does not support it or DTLS
	// failed. No SPED attribute is sent or read.
	SPEDStateOff
)

func (s SPEDState) String() string {
	switch s {
	case SPEDStateDisabled:
		return "disabled"
	case SPEDStateTentative:
		return "tentative"
	case SPEDStateConfirmed:
		return "confirmed"
	case SPEDStatePending:
		return "pending"
	case SPEDStateComplete:
		return "complete"
	case SPEDStateOff:
		return "off"
	default:
		return ErrUnknownType.Error()
	}
}

// spedPacket is a pending outgoing DTLS datagram and its CRC-32.
type spedPacket struct {
	data []byte
	crc  uint32
}

// spedController is the SPED state machine. It follows libwebrtc's
// DtlsStunPiggybackController (M147 and later): completion needs every
// datagram of the last flight acknowledged, or application data received.
// It does no I/O and no locking.
type spedController struct {
	state SPEDState
	// pending is the last DTLS flight, removed datagram by datagram as the
	// peer acknowledges it. After COMPLETE or OFF it holds datagrams that
	// still have to be sent directly.
	pending []spedPacket
	// next is the round-robin position in pending.
	next int
	// acks holds the CRC-32 of the last four distinct DTLS datagrams received.
	acks []uint32
	// dataReceived counts the embedded datagrams handed to DTLS.
	dataReceived int
}

// arm moves a disabled controller to TENTATIVE.
func (c *spedController) arm() {
	if c.state == SPEDStateDisabled {
		c.state = SPEDStateTentative
		c.acks = make([]uint32, 0, ackSizeValues)
	}
}

// active reports whether SPED attributes are sent and read.
func (c *spedController) active() bool {
	return c.state == SPEDStateTentative || c.state == SPEDStateConfirmed || c.state == SPEDStatePending
}

// capture replaces the pending flight with the DTLS datagrams of flight. A
// new flight and a retransmission both replace the previous one. Datagrams
// that are not DTLS are skipped; a flight without any leaves pending as is.
func (c *spedController) capture(flight [][]byte) {
	pending := make([]spedPacket, 0, len(flight))
	for _, datagram := range flight {
		if isDTLSPacket(datagram) {
			pending = append(pending, spedPacket{data: bytes.Clone(datagram), crc: crc32.ChecksumIEEE(datagram)})
		}
	}
	if len(pending) == 0 {
		return
	}
	c.pending = pending
	c.next = 0
}

// dataToPiggyback returns the next pending datagram, round-robin, or nil.
func (c *spedController) dataToPiggyback() []byte {
	if !c.active() || len(c.pending) == 0 {
		return nil
	}
	packet := c.pending[c.next]
	c.next = (c.next + 1) % len(c.pending)

	return packet.data
}

// acksToPiggyback returns the ACK list to send, possibly empty, and whether
// an ACK attribute must be sent at all.
func (c *spedController) acksToPiggyback() ([]uint32, bool) {
	if !c.active() {
		return nil, false
	}

	return c.acks, true
}

// receive processes the SPED attributes of an authenticated Binding request,
// or of a success response to a request that carried SPED attributes. hasAcks
// is false when the message has no valid ACK list (and no implicit ack).
//
// deliver is true when data must now be handed to DTLS; it is never true when
// deliverable is false, in which case the datagram is neither delivered nor
// acknowledged. evaluate is true when evaluateCompletion must run afterwards,
// once DTLS has processed data.
func (c *spedController) receive(
	data []byte, hasData bool, acks []uint32, hasAcks bool, deliverable bool,
) (deliver, evaluate bool) {
	if !c.active() || !c.confirm(hasData || hasAcks) {
		return false, false
	}

	if hasAcks && len(c.pending) > 0 {
		c.prune(acks)
	}

	if hasData && len(data) > 0 {
		if !isDTLSPacket(data) {
			return false, false
		}
		if deliverable {
			c.dataReceived++
			c.acknowledge(data)
			deliver = true
		}
	}

	return deliver, true
}

// confirm leaves TENTATIVE for CONFIRMED when a message carries a SPED
// attribute, and for OFF when it carries none: the peer answered or checked
// without SPED, so it does not support it. It reports whether SPED is still
// active.
func (c *spedController) confirm(hasAttribute bool) bool {
	if c.state != SPEDStateTentative {
		return true
	}
	if !hasAttribute {
		c.finish(SPEDStateOff)

		return false
	}
	c.state = SPEDStateConfirmed

	return true
}

// evaluateCompletion moves PENDING to COMPLETE once every pending datagram is
// acknowledged. It reports whether the state changed.
func (c *spedController) evaluateCompletion() bool {
	if c.state == SPEDStatePending && len(c.pending) == 0 {
		c.finish(SPEDStateComplete)

		return true
	}

	return false
}

// reportDTLSPacket adds the CRC of a DTLS datagram received outside STUN to
// the ACK list. It reports whether the list gained an entry.
func (c *spedController) reportDTLSPacket(packet []byte) bool {
	if !c.active() || !isDTLSPacket(packet) {
		return false
	}

	return c.acknowledge(packet)
}

// handshakeComplete moves to PENDING when the local DTLS handshake completes.
// The pending flight is kept until the peer acknowledges it.
func (c *spedController) handshakeComplete() {
	if c.active() {
		c.state = SPEDStatePending
	}
}

// applicationDataReceived moves PENDING to COMPLETE when DTLS application data
// or SRTP arrives. It reports whether the state changed.
func (c *spedController) applicationDataReceived() bool {
	if c.state != SPEDStatePending {
		return false
	}
	c.finish(SPEDStateComplete)

	return true
}

// failed moves to OFF after a DTLS failure and drops the pending flight. It
// reports whether the state changed.
func (c *spedController) failed() bool {
	if c.state == SPEDStateDisabled || c.state == SPEDStateOff {
		return false
	}
	c.finish(SPEDStateOff)
	c.pending = nil

	return true
}

// takePending returns and clears the pending datagrams.
func (c *spedController) takePending() []spedPacket {
	pending := c.pending
	c.pending = nil
	c.next = 0

	return pending
}

// finish moves to COMPLETE or OFF and clears the ACK list. Pending datagrams
// are kept so that they can be sent directly.
func (c *spedController) finish(state SPEDState) {
	c.state = state
	c.acks = nil
	c.next = 0
}

// prune removes acknowledged datagrams from pending, keeping the round-robin
// position as libwebrtc's PacketStash::Prune does.
func (c *spedController) prune(acks []uint32) {
	before := len(c.pending)
	c.pending = slices.DeleteFunc(c.pending, func(p spedPacket) bool {
		return slices.Contains(acks, p.crc)
	})
	removed := before - len(c.pending)
	if c.next >= removed {
		c.next -= removed
	}
	if c.next >= len(c.pending) {
		c.next = max(len(c.pending)-1, 0)
	}
}

// acknowledge adds the CRC of packet to the ACK list unless it is already
// there, evicting the oldest entry beyond four. It reports whether the list
// gained an entry.
func (c *spedController) acknowledge(packet []byte) bool {
	crc := crc32.ChecksumIEEE(packet)
	if slices.Contains(c.acks, crc) {
		return false
	}
	if len(c.acks) >= ackSizeValues {
		c.acks = append(c.acks[:0], c.acks[len(c.acks)-ackSizeValues+1:]...)
	}
	c.acks = append(c.acks, crc)

	return true
}

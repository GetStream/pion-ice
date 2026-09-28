// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"encoding/binary"
	"hash/crc32"
	"net"
	"sync"
	"sync/atomic"

	"github.com/pion/stun/v4"
)

// spedSession is the SPED state of an Agent.
type spedSession struct {
	mu       sync.Mutex
	ctrl     spedController
	callback func(packet []byte, rAddr net.Addr)
	// state mirrors ctrl.state for reads without the lock.
	state atomic.Int32
}

// load returns the current state without taking the lock.
func (s *spedSession) load() SPEDState {
	return SPEDState(s.state.Load())
}

// EnableSPED enables SPED (STUN Protocol for Embedding DTLS) and moves it to
// SPEDStateTentative. From then on every Binding request and success response
// carries a DTLS-in-STUN-ACK attribute, possibly empty, and a DTLS-in-STUN
// attribute whenever a DTLS datagram is pending and fits, until SPED reaches
// SPEDStateComplete or SPEDStateOff.
//
// SPED must be enabled before connectivity checks start (StartDial,
// StartAccept, Dial or Accept): a peer such as libwebrtc turns SPED off for the
// whole session after one message without SPED attributes. It returns
// ErrSPEDAfterStart otherwise. Enabling it again is a no-op; once off or
// complete, SPED is not re-enabled.
//
// The semantics follow libwebrtc M147 and later: SPED completes when the local
// DTLS handshake is complete and the peer acknowledged every datagram of the
// last flight, or when application data arrives. The DTLS side reports to the
// agent through SetDTLSCallback, Piggyback, ReportDTLSPacket,
// SetDTLSHandshakeComplete, ApplicationDataReceived and SetDTLSFailed.
func (a *Agent) EnableSPED() error {
	if err := a.loop.Err(); err != nil {
		return err
	}
	select {
	case <-a.startedCh:
		return ErrSPEDAfterStart
	default:
	}

	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()
	before := a.sped.ctrl.state
	a.sped.ctrl.arm()
	a.spedUpdateLocked(before)

	return nil
}

// SPEDState returns the current SPED state.
func (a *Agent) SPEDState() SPEDState {
	return a.sped.load()
}

// SetDTLSCallback sets the function that receives the DTLS datagrams embedded
// in STUN by the peer. Each datagram is acknowledged to the peer only if a
// callback is set when it arrives.
//
// The callback runs synchronously on the agent's internal loop, while the
// Binding request that carried the datagram waits for its response: a flight
// queued with Piggyback before the callback returns rides that response. The
// callback must not block, and must not call Agent or Conn methods that wait
// for the agent's loop (the SPED methods and WriteDTLS do not). packet is only
// valid until the callback returns.
func (a *Agent) SetDTLSCallback(callback func(packet []byte, rAddr net.Addr)) {
	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()
	a.sped.callback = callback
}

// Piggyback queues one DTLS flight, all its datagrams in order, to be embedded
// in STUN. A new flight, or a retransmission of the current one, replaces the
// previous flight. Datagrams are embedded round-robin, one per Binding request
// or response, and removed once the peer acknowledges them. Datagrams that are
// not DTLS are skipped; the datagrams are copied.
//
// It returns false when the agent does not take the flight: SPED is disabled,
// or SPED is complete or off and a candidate pair is selected. The caller then
// sends the flight directly like any DTLS datagram. It returns true otherwise.
// When SPED is complete or off and no pair is selected yet, the flight is held
// and sent directly on the pair that gets selected.
//
// It may be called from the DTLS callback.
func (a *Agent) Piggyback(flight [][]byte) bool {
	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()

	switch a.sped.ctrl.state {
	case SPEDStateDisabled:
		return false
	case SPEDStateComplete, SPEDStateOff:
		if a.getSelectedPair() != nil {
			return false
		}
	default:
	}
	a.sped.ctrl.capture(flight)

	return true
}

// ReportDTLSPacket reports a DTLS datagram received directly, outside STUN,
// so that its CRC-32 is acknowledged to the peer. Datagrams received in STUN
// are acknowledged by the agent itself.
func (a *Agent) ReportDTLSPacket(packet []byte) {
	if !a.spedActive() {
		return
	}

	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()
	a.sped.ctrl.reportDTLSPacket(packet)
}

// SetDTLSHandshakeComplete reports that the local DTLS handshake completed.
// SPED moves to SPEDStatePending and keeps the last flight until the peer
// acknowledges it.
func (a *Agent) SetDTLSHandshakeComplete() {
	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()
	before := a.sped.ctrl.state
	a.sped.ctrl.handshakeComplete()
	a.spedUpdateLocked(before)
}

// ApplicationDataReceived reports that DTLS application data (SCTP) or SRTP
// was received. In SPEDStatePending it completes SPED, since the peer's
// handshake must be complete too, and sends any unacknowledged datagram
// directly. It is cheap to call for every packet.
func (a *Agent) ApplicationDataReceived() {
	if a.sped.load() != SPEDStatePending {
		return
	}

	a.sped.mu.Lock()
	before := a.sped.ctrl.state
	a.sped.ctrl.applicationDataReceived()
	a.spedUpdateLocked(before)
	pair, packets := a.spedTakeFlushLocked()
	a.sped.mu.Unlock()

	a.spedSend(pair, packets)
}

// SetDTLSFailed reports that the DTLS handshake failed. SPED turns off and the
// pending flight is dropped.
func (a *Agent) SetDTLSFailed() {
	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()
	before := a.sped.ctrl.state
	a.sped.ctrl.failed()
	a.spedUpdateLocked(before)
}

// spedActive reports whether SPED attributes are sent and read.
func (a *Agent) spedActive() bool {
	switch a.sped.load() {
	case SPEDStateTentative, SPEDStateConfirmed, SPEDStatePending:
		return true
	default:
		return false
	}
}

// appendSPEDAttributes appends the SPED attributes to a Binding request or
// success response while SPED is active. It must be followed by
// MESSAGE-INTEGRITY. When SPED is disabled attrs is returned unchanged.
func (a *Agent) appendSPEDAttributes(attrs []stun.Setter) []stun.Setter {
	if !a.spedActive() {
		return attrs
	}

	return append(attrs, spedSetter{session: &a.sped})
}

// spedSetter adds DTLS-in-STUN-ACK and DTLS-in-STUN to a message within the
// MaxSTUNBindingBody budget, as libwebrtc's
// Connection::MaybeAddDtlsPiggybackingAttributes does.
type spedSetter struct {
	session *spedSession
}

// AddTo implements stun.Setter.
func (s spedSetter) AddTo(msg *stun.Message) error {
	s.session.mu.Lock()
	defer s.session.mu.Unlock()

	acks, ok := s.session.ctrl.acksToPiggyback()
	if !ok {
		return nil
	}
	data := s.session.ctrl.dataToPiggyback()

	var value [ackSizeBytes]byte
	switch body := int(msg.Length); {
	case body+stunAttributeHeaderLen+len(acks)*4 <= MaxSTUNBindingBody:
		for i, crc := range acks {
			binary.BigEndian.PutUint32(value[i*4:], crc)
		}
		msg.Add(stun.AttrDtlsInStunAck, value[:len(acks)*4])
	case body+stunAttributeHeaderLen <= MaxSTUNBindingBody:
		msg.Add(stun.AttrDtlsInStunAck, nil)
	default:
		return nil
	}

	if data != nil && int(msg.Length)+stunAttributeHeaderLen+len(data) <= MaxSTUNBindingBody {
		msg.Add(stun.AttrDtlsInStun, data)
	}

	return nil
}

// spedRequestSent records the SPED attributes of an outgoing Binding request,
// used to process its response.
func (a *Agent) spedRequestSent(msg *stun.Message, request *bindingRequest) {
	if a.sped.load() == SPEDStateDisabled {
		return
	}
	if data, err := msg.Get(stun.AttrDtlsInStun); err == nil {
		request.spedSent = true
		request.spedDataSent = true
		request.spedDataCRC = crc32.ChecksumIEEE(data)
	} else if msg.Contains(stun.AttrDtlsInStunAck) {
		request.spedSent = true
	}
}

// handleSPEDRequest processes the SPED attributes of an authenticated Binding
// request. It runs before the response is built, so that a flight queued by
// the DTLS callback rides the response.
func (a *Agent) handleSPEDRequest(msg *stun.Message, remote Candidate) {
	if !a.spedActive() {
		return
	}
	a.receiveSPED(spedAttributesFrom(msg), remote)
}

// handleSPEDResponse processes the SPED attributes of a Binding success
// response, if its request carried SPED attributes.
func (a *Agent) handleSPEDResponse(msg *stun.Message, request *bindingRequest, remote Candidate) {
	if !request.spedSent || !a.spedActive() {
		return
	}
	attrs := spedAttributesFrom(msg)
	if attrs.hasAck && request.spedDataSent {
		// A response with an ACK attribute, even an empty or malformed one,
		// implicitly acknowledges the DATA of its request.
		attrs.acks = append(attrs.acks, request.spedDataCRC)
		attrs.ackValid = true
	}
	a.receiveSPED(attrs, remote)
}

// receiveSPED runs the controller on the SPED attributes of a message, hands
// embedded DTLS to the callback, then evaluates completion.
func (a *Agent) receiveSPED(attrs spedAttributes, remote Candidate) {
	a.sped.mu.Lock()
	callback := a.sped.callback
	before := a.sped.ctrl.state
	deliver, evaluate := a.sped.ctrl.receive(
		attrs.data, attrs.hasData, attrs.acks, attrs.hasAck && attrs.ackValid, callback != nil,
	)
	a.spedUpdateLocked(before)
	pair, packets := a.spedTakeFlushLocked()
	a.sped.mu.Unlock()
	a.spedSend(pair, packets)

	if deliver {
		callback(attrs.data, remote.addr())
	}
	if !evaluate {
		return
	}

	a.sped.mu.Lock()
	before = a.sped.ctrl.state
	a.sped.ctrl.evaluateCompletion()
	a.spedUpdateLocked(before)
	pair, packets = a.spedTakeFlushLocked()
	a.sped.mu.Unlock()
	a.spedSend(pair, packets)
}

// spedPairSelected sends the datagrams held after SPED completed or turned off
// on the newly selected pair.
func (a *Agent) spedPairSelected() {
	if a.sped.load() == SPEDStateDisabled {
		return
	}

	a.sped.mu.Lock()
	pair, packets := a.spedTakeFlushLocked()
	a.sped.mu.Unlock()
	a.spedSend(pair, packets)
}

// spedTakeFlushLocked returns the datagrams still pending after SPED completed
// or turned off, and the pair to send them on directly. It returns nothing
// while SPED is active or while no pair can carry them yet.
func (a *Agent) spedTakeFlushLocked() (*CandidatePair, []spedPacket) {
	state := a.sped.ctrl.state
	if (state != SPEDStateComplete && state != SPEDStateOff) || len(a.sped.ctrl.pending) == 0 {
		return nil, nil
	}
	pair := a.getSelectedPair()
	if pair == nil {
		return nil, nil
	}

	return pair, a.sped.ctrl.takePending()
}

// spedSend writes DTLS datagrams directly on pair.
func (a *Agent) spedSend(pair *CandidatePair, packets []spedPacket) {
	for _, packet := range packets {
		n, err := pair.Write(packet.data)
		if err != nil {
			a.log.Debugf("Failed to send pending DTLS datagram on %s: %v", pair, err)

			continue
		}
		pair.UpdatePacketSent(n)
	}
}

// spedUpdateLocked publishes the controller state and logs its transitions.
func (a *Agent) spedUpdateLocked(before SPEDState) {
	after := a.sped.ctrl.state
	a.sped.state.Store(int32(after))
	if before != after {
		a.log.Debugf("SPED state changed: %s -> %s", before, after)
	}
}

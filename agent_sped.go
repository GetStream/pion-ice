// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/pion/stun/v4"
)

// spedSession is the SPED state of an Agent.
type spedSession struct {
	mu       sync.Mutex
	ctrl     spedController
	callback func(packet []byte, rAddr net.Addr)
	// pair is where DTLS can be written directly before a pair is selected:
	// the best pair that answered a check (full agent) or sent an
	// authenticated check (lite agent) while SPED was active.
	pair *CandidatePair
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
// or SPED is complete or off and WriteDTLS can send the flight directly. The
// caller then sends it directly like any DTLS datagram. It returns true
// otherwise. When SPED is complete or off and WriteDTLS has no pair yet, the
// flight is held and sent directly on the pair that gets selected.
//
// While SPED is active the caller should also write the flight with
// WriteDTLS, which succeeds once a pair is usable: the peer then gets it
// directly as well as in STUN, as libwebrtc does. A full agent also sends a
// check on the selected pair, or the best valid pair, for the flight to ride.
//
// It may be called from the DTLS callback.
func (a *Agent) Piggyback(flight [][]byte) bool {
	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()

	switch a.sped.ctrl.state {
	case SPEDStateDisabled:
		return false
	case SPEDStateComplete, SPEDStateOff:
		if a.getSelectedPair() != nil || a.spedDirectPairLocked() != nil {
			return false
		}
	default:
		a.requestSPEDCheck()
	}
	a.sped.ctrl.capture(flight)

	return true
}

// ReportDTLSPacket reports a DTLS datagram received directly, outside STUN,
// so that its CRC-32 is acknowledged to the peer. Datagrams received in STUN
// are acknowledged by the agent itself. A full agent sends a check to carry a
// new acknowledgement.
func (a *Agent) ReportDTLSPacket(packet []byte) {
	if !a.spedActive() {
		return
	}

	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()
	if a.sped.ctrl.reportDTLSPacket(packet) {
		a.requestSPEDCheck()
	}
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

// WriteDTLS writes one DTLS datagram directly, outside STUN. It uses the
// selected pair or, before a pair is selected and while the peer is known to
// support SPED (SPEDStateConfirmed, SPEDStatePending or SPEDStateComplete),
// the best pair that proved usable:
//   - for a full agent, a pair that answered a check;
//   - for a lite agent, a pair from which an authenticated check arrived. A
//     lite agent otherwise cannot send before the peer nominates a pair.
//
// It returns ErrNoCandidatePairs when there is no such pair; the datagram is
// then only delivered through STUN. Unlike Conn.Write it never waits for the
// agent's loop, so it may be called from the DTLS callback, and it does not
// count the bytes in Conn.BytesSent.
func (a *Agent) WriteDTLS(packet []byte) (int, error) {
	if err := a.loop.Err(); err != nil {
		return 0, err
	}
	if stun.IsMessage(packet) {
		return 0, errWriteSTUNMessageToIceConn
	}

	pair := a.getSelectedPair()
	if pair == nil {
		pair = a.spedDirectPair()
	}
	if pair == nil {
		return 0, ErrNoCandidatePairs
	}

	n, err := pair.Write(packet)
	if n > 0 {
		pair.UpdatePacketSent(n)
	}

	return n, err
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
// the DTLS callback rides the response. Its result goes to spedRequestHandled
// once the response is sent.
func (a *Agent) handleSPEDRequest(msg *stun.Message, local, remote Candidate) bool {
	if !a.spedActive() {
		return false
	}
	var usable *CandidatePair
	if a.lite && !a.isControlling.Load() {
		// The controlled selector adds the pair for this request anyway;
		// adding it here lets DTLS produced by the callback go out directly.
		pair := a.findPair(local, remote)
		if pair == nil {
			pair = a.addPair(local, remote)
		}
		if a.spedPairUsable(pair) {
			usable = pair
		}
	}
	_, evaluate := a.receiveSPED(spedAttributesFrom(msg), remote, usable)

	return evaluate
}

// handleSPEDResponse processes the SPED attributes of a Binding success
// response, if its request carried SPED attributes.
func (a *Agent) handleSPEDResponse(msg *stun.Message, request *bindingRequest, pair *CandidatePair) {
	if !a.spedActive() {
		return
	}
	var usable *CandidatePair
	if a.spedPairUsable(pair) {
		usable = pair
	}
	if !request.spedSent {
		return
	}
	attrs := spedAttributesFrom(msg)
	if attrs.hasAck && request.spedDataSent {
		// A response with an ACK attribute, even an empty or malformed one,
		// implicitly acknowledges the DATA of its request.
		attrs.acks = append(attrs.acks, request.spedDataCRC)
		attrs.ackValid = true
	}
	delivered, evaluate := a.receiveSPED(attrs, pair.Remote, usable)
	if evaluate {
		a.spedEvaluateCompletion()
	}
	if delivered {
		// Acknowledge the datagram without waiting for the next check.
		a.requestSPEDCheck()
	}
}

// spedRequestHandled evaluates completion after the response to a request
// with SPED attributes was sent, so that the response still acknowledges the
// peer's last flight and the peer can complete too.
func (a *Agent) spedRequestHandled(evaluate bool) {
	if evaluate {
		a.spedEvaluateCompletion()
	}
}

// spedPairUsable records that DTLS may be written directly on pair before a
// pair is selected, if it is better than the current one. It reports whether
// pair is the first usable pair.
func (a *Agent) spedPairUsable(pair *CandidatePair) bool {
	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()
	first := a.sped.pair == nil
	if first || a.sped.pair.priority() < pair.priority() {
		a.sped.pair = pair
	}

	return first
}

// spedPairsReset forgets the usable pair when the agent drops its pairs.
func (a *Agent) spedPairsReset() {
	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()
	a.sped.pair = nil
}

// spedDirectPair returns the usable pair while the peer is known to support
// SPED, or nil.
func (a *Agent) spedDirectPair() *CandidatePair {
	a.sped.mu.Lock()
	defer a.sped.mu.Unlock()

	return a.spedDirectPairLocked()
}

func (a *Agent) spedDirectPairLocked() *CandidatePair {
	switch a.sped.ctrl.state {
	case SPEDStateConfirmed, SPEDStatePending, SPEDStateComplete:
		return a.sped.pair
	default:
		return nil
	}
}

// receiveSPED runs the controller on the SPED attributes of a message and hands
// embedded DTLS to the callback. It reports whether a datagram was delivered,
// and whether spedEvaluateCompletion must run.
//
// usable is the pair the message made the first usable pair, or nil. Once the
// peer is known to support SPED, the datagrams still pending are sent directly
// on it before the callback runs, as libwebrtc's FlushPendingDtlsPacket does
// when ICE first becomes writable: the rest of a flight that needs several
// messages then does not wait for the next checks.
func (a *Agent) receiveSPED(attrs spedAttributes, remote Candidate, usable *CandidatePair) (delivered, evaluate bool) {
	a.sped.mu.Lock()
	callback := a.sped.callback
	before := a.sped.ctrl.state
	deliver, evaluate := a.sped.ctrl.receive(
		attrs.data, attrs.hasData, attrs.acks, attrs.hasAck && attrs.ackValid, callback != nil,
	)
	a.spedUpdateLocked(before)
	pair, packets := a.spedTakeFlushLocked()
	var usablePackets []spedPacket
	if usable != nil && a.spedDirectPairLocked() != nil {
		usablePackets = slices.Clone(a.sped.ctrl.pending)
	}
	a.sped.mu.Unlock()
	a.spedSend(pair, packets)
	a.spedSend(usable, usablePackets)

	if deliver {
		callback(attrs.data, remote.addr())
	}

	return deliver, evaluate
}

// spedEvaluateCompletion completes SPED once the local handshake is complete
// and every pending datagram is acknowledged.
func (a *Agent) spedEvaluateCompletion() {
	a.sped.mu.Lock()
	before := a.sped.ctrl.state
	a.sped.ctrl.evaluateCompletion()
	a.spedUpdateLocked(before)
	pair, packets := a.spedTakeFlushLocked()
	a.sped.mu.Unlock()
	a.spedSend(pair, packets)
}

// requestSPEDCheck asks a full agent for a check on the selected pair, or the
// best valid pair, so that a queued flight or a new acknowledgement rides it
// without waiting for the next scheduled check or keepalive. Once a pair is
// selected checks only run every keepalive interval, and the DTLS handshake
// would otherwise wait for that or for a DTLS retransmission. Lite agents do
// not send checks. Requests are coalesced; it never blocks.
func (a *Agent) requestSPEDCheck() {
	if a.lite {
		return
	}
	select {
	case a.spedCheck <- struct{}{}:
	default:
	}
}

// spedChecks sends the checks requested by requestSPEDCheck until the agent
// closes. It runs for full agents with SPED enabled.
func (a *Agent) spedChecks() {
	for {
		select {
		case <-a.spedCheck:
			if err := a.loop.Run(a.loop, func(context.Context) { a.spedCheckNow() }); err != nil {
				return
			}
		case <-a.loop.Done():
			return
		}
	}
}

// spedCheckNow sends a check on the selected pair, or the best valid pair,
// while SPED is active.
func (a *Agent) spedCheckNow() {
	if !a.spedActive() {
		return
	}
	pair := a.getSelectedPair()
	if pair == nil {
		pair = a.getBestValidCandidatePair()
	}
	if pair == nil {
		return
	}
	a.getSelector().PingCandidate(pair.Local, pair.Remote)
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
// while SPED is active or while no pair can carry them yet. After a fallback
// the datagrams wait for a selected pair: a peer without SPED only starts DTLS
// once ICE connects.
func (a *Agent) spedTakeFlushLocked() (*CandidatePair, []spedPacket) {
	state := a.sped.ctrl.state
	if (state != SPEDStateComplete && state != SPEDStateOff) || len(a.sped.ctrl.pending) == 0 {
		return nil, nil
	}
	pair := a.getSelectedPair()
	if pair == nil {
		pair = a.spedDirectPairLocked()
	}
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

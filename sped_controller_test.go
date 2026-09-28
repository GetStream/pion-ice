// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"hash/crc32"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// DTLS 1.2 flights from libwebrtc's dtls_stun_piggyback_controller_unittest.cc,
// each truncated to its first fragment.
func spedTestFlight(seq, msgSeqHi, msgSeqLo byte) []byte {
	return []byte{
		0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, seq,
		0x00, 0x0c, 0x0e, 0x00, 0x00, 0x00, msgSeqHi, msgSeqLo, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

var (
	spedFlight1 = spedTestFlight(1, 0x12, 0x34) //nolint:gochecknoglobals
	spedFlight2 = spedTestFlight(2, 0x43, 0x21) //nolint:gochecknoglobals
	spedFlight3 = spedTestFlight(3, 0x44, 0x44) //nolint:gochecknoglobals
	spedFlight4 = spedTestFlight(4, 0x54, 0x86) //nolint:gochecknoglobals
)

func spedFakePacket(number uint16) []byte {
	packet := spedTestFlight(1, byte(number>>8), byte(number&0xff))

	return packet
}

func crcs(packets ...[]byte) []uint32 {
	out := make([]uint32, 0, len(packets))
	for _, p := range packets {
		out = append(out, crc32.ChecksumIEEE(p))
	}

	return out
}

// spedPeers mirrors the libwebrtc controller test fixture: a DTLS client and a
// DTLS server exchanging SPED attributes directly between two controllers.
type spedPeers struct {
	client, server         spedController
	clientSink, serverSink [][]byte
}

func newSPEDPeers() *spedPeers {
	peers := &spedPeers{}
	peers.client.arm()
	peers.server.arm()

	return peers
}

// exchange embeds packet (or nothing when packet is empty) from one side into
// a STUN message and has the other side receive it.
func (p *spedPeers) exchange(from, to *spedController, sink *[][]byte, packet []byte) {
	if len(packet) > 0 {
		from.capture([][]byte{packet})
	} else {
		from.pending = nil
	}
	data := from.dataToPiggyback()
	acks, hasAcks := from.acksToPiggyback()
	deliver, evaluate := to.receive(data, data != nil, slices.Clone(acks), hasAcks, true)
	if deliver {
		*sink = append(*sink, data)
	}
	if evaluate {
		to.evaluateCompletion()
	}
}

// direct sends packet as plain DTLS and has the other side report it.
func (p *spedPeers) direct(from, to *spedController, packet []byte) {
	if len(packet) > 0 {
		from.capture([][]byte{packet})
	} else {
		from.pending = nil
	}
	to.reportDTLSPacket(packet)
}

func (p *spedPeers) clientToServer(packet []byte) {
	p.exchange(&p.client, &p.server, &p.serverSink, packet)
}

func (p *spedPeers) clientToServerDirect(packet []byte) {
	p.direct(&p.client, &p.server, packet)
}

func (p *spedPeers) serverToClient(packet []byte) {
	p.exchange(&p.server, &p.client, &p.clientSink, packet)
	p.maybeHandshakeComplete(packet)
}

func (p *spedPeers) serverToClientDirect(packet []byte) {
	p.direct(&p.server, &p.client, packet)
	p.maybeHandshakeComplete(packet)
}

// maybeHandshakeComplete assumes DTLS 1.2: flight 4 completes both sides.
func (p *spedPeers) maybeHandshakeComplete(packet []byte) {
	if slices.Equal(packet, spedFlight4) {
		p.server.handshakeComplete()
		p.client.handshakeComplete()
	}
}

func (p *spedPeers) disableSupport(tb testing.TB, ctrl *spedController) {
	tb.Helper()

	require.Equal(tb, SPEDStateTentative, ctrl.state)
	ctrl.receive(nil, false, nil, false, true)
	require.Equal(tb, SPEDStateOff, ctrl.state)
}

func (p *spedPeers) handshakeThroughFlight4(tb testing.TB) {
	tb.Helper()

	p.clientToServer(spedFlight1)
	require.Equal(tb, SPEDStateConfirmed, p.server.state)
	p.serverToClient(spedFlight2)
	require.Equal(tb, SPEDStateConfirmed, p.client.state)

	p.clientToServer(spedFlight3)
	p.serverToClient(spedFlight4)
	require.Equal(tb, SPEDStatePending, p.server.state)
	require.Equal(tb, SPEDStatePending, p.client.state)
}

// The tests below port libwebrtc's DtlsStunPiggybackControllerTest cases
// (p2p/dtls/dtls_stun_piggyback_controller_unittest.cc @ 574c6a5c).
func TestSPEDController(t *testing.T) { //nolint:maintidx
	t.Run("BasicHandshake", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.handshakeThroughFlight4(t)

		// Post-handshake ACK.
		peers.serverToClient(nil)
		require.Equal(t, SPEDStateComplete, peers.client.state)
		peers.clientToServer(nil)
		require.Equal(t, SPEDStateComplete, peers.server.state)

		require.Equal(t, [][]byte{spedFlight1, spedFlight3}, peers.serverSink)
		require.Equal(t, [][]byte{spedFlight2, spedFlight4}, peers.clientSink)
	})

	t.Run("BasicHandshakeCompleteWithApplicationData", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.handshakeThroughFlight4(t)

		require.True(t, peers.client.applicationDataReceived())
		require.Equal(t, SPEDStateComplete, peers.client.state)
		require.True(t, peers.server.applicationDataReceived())
		require.Equal(t, SPEDStateComplete, peers.server.state)
	})

	t.Run("BasicHandshakeEarlyApplicationDataDoesNotComplete", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.clientToServer(spedFlight1)
		peers.serverToClient(spedFlight2)
		peers.clientToServer(spedFlight3)
		require.Equal(t, SPEDStateConfirmed, peers.server.state)

		// SRTP arriving before the local handshake completes.
		require.False(t, peers.server.applicationDataReceived())
		require.Equal(t, SPEDStateConfirmed, peers.server.state)

		peers.serverToClient(spedFlight4)
		require.Equal(t, SPEDStatePending, peers.server.state)
		require.Equal(t, SPEDStatePending, peers.client.state)

		require.True(t, peers.client.applicationDataReceived())
		require.True(t, peers.server.applicationDataReceived())
		require.Equal(t, SPEDStateComplete, peers.client.state)
		require.Equal(t, SPEDStateComplete, peers.server.state)
	})

	t.Run("FirstClientPacketLost", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.serverToClient(nil)
		peers.clientToServer(spedFlight1)
		require.Equal(t, SPEDStateConfirmed, peers.server.state)
		require.Equal(t, SPEDStateConfirmed, peers.client.state)

		peers.serverToClient(spedFlight2)
		peers.clientToServer(spedFlight3)
		require.Equal(t, SPEDStateConfirmed, peers.server.state)
		require.Equal(t, SPEDStateConfirmed, peers.client.state)

		peers.serverToClient(spedFlight4)
		peers.clientToServer(nil)
		require.Equal(t, SPEDStateComplete, peers.server.state)
		require.Equal(t, SPEDStatePending, peers.client.state)

		peers.serverToClient(nil)
		require.Equal(t, SPEDStateComplete, peers.client.state)
	})

	t.Run("NotSupportedByServer", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.disableSupport(t, &peers.server)

		peers.clientToServer(spedFlight1)
		peers.serverToClient(nil)
		require.Equal(t, SPEDStateOff, peers.client.state)
		// The ClientHello is kept so that it can be sent directly.
		require.Equal(t, []spedPacket{{data: spedFlight1, crc: crc32.ChecksumIEEE(spedFlight1)}}, peers.client.pending)
		require.Empty(t, peers.serverSink)
	})

	t.Run("NotSupportedByServerClientReceives", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.disableSupport(t, &peers.server)

		peers.serverToClient(nil)
		require.Equal(t, SPEDStateOff, peers.client.state)
	})

	t.Run("NotSupportedByClient", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.disableSupport(t, &peers.client)

		peers.serverToClient(nil)
		peers.clientToServer(nil)
		require.Equal(t, SPEDStateOff, peers.server.state)
	})

	t.Run("SomeRequestsDoNotGoThrough", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.serverToClient(nil)
		peers.clientToServer(spedFlight1)
		require.Equal(t, SPEDStateConfirmed, peers.server.state)
		require.Equal(t, SPEDStateConfirmed, peers.client.state)

		peers.clientToServer(spedFlight1)
		peers.serverToClient(spedFlight2)
		require.Equal(t, SPEDStateConfirmed, peers.server.state)
		require.Equal(t, SPEDStateConfirmed, peers.client.state)

		peers.clientToServer(spedFlight3)
		peers.serverToClient(spedFlight4)
		require.Equal(t, SPEDStatePending, peers.server.state)
		require.Equal(t, SPEDStatePending, peers.client.state)

		peers.clientToServer(nil)
		require.Equal(t, SPEDStateComplete, peers.server.state)
		peers.serverToClient(nil)
		require.Equal(t, SPEDStateComplete, peers.client.state)
	})

	t.Run("LossOnPostHandshakeAck", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.handshakeThroughFlight4(t)

		peers.serverToClient(nil)
		peers.clientToServer(nil)
		require.Equal(t, SPEDStateComplete, peers.server.state)
		require.Equal(t, SPEDStateComplete, peers.client.state)
	})

	t.Run("UnsupportedStateAfterFallbackHandshakeRemainsOff", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.disableSupport(t, &peers.client)
		peers.disableSupport(t, &peers.server)

		peers.client.handshakeComplete()
		require.Equal(t, SPEDStateOff, peers.client.state)
		peers.server.handshakeComplete()
		require.Equal(t, SPEDStateOff, peers.server.state)
	})

	t.Run("BasicHandshakeAckData", func(t *testing.T) {
		peers := newSPEDPeers()
		for _, ctrl := range []*spedController{&peers.server, &peers.client} {
			acks, ok := ctrl.acksToPiggyback()
			require.True(t, ok)
			require.Empty(t, acks)
		}

		peers.clientToServer(spedFlight1)
		peers.serverToClient(spedFlight2)
		require.Equal(t, crcs(spedFlight1), peers.server.acks)
		require.Equal(t, crcs(spedFlight2), peers.client.acks)

		peers.clientToServer(spedFlight3)
		peers.serverToClient(spedFlight4)
		require.Equal(t, crcs(spedFlight1, spedFlight3), peers.server.acks)
		require.Equal(t, crcs(spedFlight2, spedFlight4), peers.client.acks)

		peers.serverToClient(nil)
		peers.clientToServer(nil)
		require.Equal(t, SPEDStateComplete, peers.server.state)
		require.Equal(t, SPEDStateComplete, peers.client.state)
		for _, ctrl := range []*spedController{&peers.server, &peers.client} {
			_, ok := ctrl.acksToPiggyback()
			require.False(t, ok)
		}
	})

	t.Run("UnwrappedHandshakeAckData", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.clientToServer(spedFlight1)
		peers.serverToClient(spedFlight2)
		require.Equal(t, crcs(spedFlight1), peers.server.acks)
		require.Equal(t, crcs(spedFlight2), peers.client.acks)

		// Flights 3 and 4 are sent directly, not embedded.
		peers.clientToServerDirect(spedFlight3)
		peers.serverToClientDirect(spedFlight4)
		require.Equal(t, crcs(spedFlight1, spedFlight3), peers.server.acks)
		require.Equal(t, crcs(spedFlight2, spedFlight4), peers.client.acks)

		peers.serverToClient(nil)
		peers.clientToServer(nil)
		require.Equal(t, SPEDStateComplete, peers.server.state)
		require.Equal(t, SPEDStateComplete, peers.client.state)
	})

	t.Run("AckDataNoDuplicates", func(t *testing.T) {
		peers := newSPEDPeers()
		peers.clientToServer(spedFlight1)
		require.Equal(t, crcs(spedFlight1), peers.server.acks)
		peers.clientToServer(spedFlight3)
		require.Equal(t, crcs(spedFlight1, spedFlight3), peers.server.acks)
		peers.clientToServer(spedFlight1)
		require.Equal(t, crcs(spedFlight1, spedFlight3), peers.server.acks)
	})

	t.Run("AckDataNoDuplicatesFromDualReporting", func(t *testing.T) {
		var server spedController
		server.arm()
		server.receive(spedFlight1, true, []uint32{}, true, true)
		require.False(t, server.reportDTLSPacket(spedFlight1))
		require.Equal(t, crcs(spedFlight1), server.acks)
	})

	t.Run("IgnoresNonDTLSData", func(t *testing.T) {
		var server spedController
		server.arm()
		deliver, evaluate := server.receive([]byte("dropme"), true, nil, false, true)
		require.False(t, deliver)
		require.False(t, evaluate)
		require.Zero(t, server.dataReceived)
		require.Empty(t, server.acks)
		// A message with (non-DTLS) data still shows support.
		require.Equal(t, SPEDStateConfirmed, server.state)
	})

	t.Run("DontSendAckedPackets", func(t *testing.T) {
		var server spedController
		server.arm()
		server.capture([][]byte{spedFlight1})
		require.NotNil(t, server.dataToPiggyback())
		server.receive(nil, false, crcs(spedFlight1), true, true)
		require.Nil(t, server.dataToPiggyback())
	})

	t.Run("LimitAckSize", func(t *testing.T) {
		var server spedController
		server.arm()
		flight5 := spedFakePacket(0x5487)
		for i, flight := range [][]byte{spedFlight1, spedFlight2, spedFlight3, spedFlight4} {
			server.receive(flight, true, nil, false, true)
			require.Len(t, server.acks, i+1)
		}
		server.receive(flight5, true, nil, false, true)
		require.Equal(t, crcs(spedFlight2, spedFlight3, spedFlight4, flight5), server.acks)
	})

	t.Run("EmptyDataDoesNotClearAck", func(t *testing.T) {
		var server spedController
		server.arm()
		server.receive(spedFlight1, true, nil, false, true)
		require.Len(t, server.acks, 1)

		// No data does not mean the ACK list can be cleared: packets can be
		// reordered, and a peer may need two datagrams (post-quantum) before
		// it answers.
		server.receive(nil, false, crcs(spedFlight1), true, true)
		require.Equal(t, crcs(spedFlight1), server.acks)
	})

	t.Run("MultiPacketRoundRobin", func(t *testing.T) {
		var server spedController
		server.arm()
		server.capture([][]byte{spedFlight1, spedFlight2, spedFlight3})
		require.Equal(t, spedFlight1, server.dataToPiggyback())
		require.Equal(t, spedFlight2, server.dataToPiggyback())
		require.Equal(t, spedFlight3, server.dataToPiggyback())

		server.receive(nil, false, crcs(spedFlight1), true, true)
		require.Equal(t, spedFlight2, server.dataToPiggyback())
		require.Equal(t, spedFlight3, server.dataToPiggyback())

		server.receive(nil, false, crcs(spedFlight3), true, true)
		require.Equal(t, spedFlight2, server.dataToPiggyback())
		require.Equal(t, spedFlight2, server.dataToPiggyback())
	})

	t.Run("DuplicateAck", func(t *testing.T) {
		var server spedController
		server.arm()
		server.capture([][]byte{spedFlight1})
		server.receive(nil, false, crcs(spedFlight1, spedFlight1), true, true)
		require.Empty(t, server.pending)
	})
}

// TestSPEDControllerM147 covers where libwebrtc M147 and later differ from the
// M146 "closing handshake" rules that pion/ice v5 and LiveKit implement
// (libwebrtc commits 5c7cca0f, e7ad41ca, 8d0a4663).
func TestSPEDControllerM147(t *testing.T) {
	pendingWithUnackedFlight := func(t *testing.T) *spedController {
		t.Helper()

		var ctrl spedController
		ctrl.arm()
		ctrl.receive(nil, false, []uint32{}, true, true)
		ctrl.capture([][]byte{spedFlight3})
		ctrl.handshakeComplete()
		require.Equal(t, SPEDStatePending, ctrl.state)

		return &ctrl
	}

	t.Run("MessageWithoutDataOrAckDoesNotComplete", func(t *testing.T) {
		// M146: PENDING plus a message without DATA and ACK completed.
		ctrl := pendingWithUnackedFlight(t)
		_, evaluate := ctrl.receive(nil, false, nil, false, true)
		require.True(t, evaluate)
		require.False(t, ctrl.evaluateCompletion())
		require.Equal(t, SPEDStatePending, ctrl.state)
		require.Len(t, ctrl.pending, 1)
	})

	t.Run("AckWithoutDataDoesNotComplete", func(t *testing.T) {
		// M146: PENDING plus an ACK without DATA completed.
		ctrl := pendingWithUnackedFlight(t)
		ctrl.receive(nil, false, crcs(spedFlight1), true, true)
		require.False(t, ctrl.evaluateCompletion())
		require.Equal(t, SPEDStatePending, ctrl.state)
	})

	t.Run("EmptyDataDoesNotComplete", func(t *testing.T) {
		ctrl := pendingWithUnackedFlight(t)
		ctrl.receive([]byte{}, true, []uint32{}, true, true)
		require.False(t, ctrl.evaluateCompletion())
		require.Equal(t, SPEDStatePending, ctrl.state)
	})

	t.Run("CompletesOnceLastFlightAcked", func(t *testing.T) {
		ctrl := pendingWithUnackedFlight(t)
		ctrl.receive(nil, false, crcs(spedFlight3), true, true)
		require.True(t, ctrl.evaluateCompletion())
		require.Equal(t, SPEDStateComplete, ctrl.state)
	})

	t.Run("MessageWithoutDataKeepsAcks", func(t *testing.T) {
		// M146: a message without DATA cleared the ACK list.
		var ctrl spedController
		ctrl.arm()
		ctrl.receive(spedFlight2, true, []uint32{}, true, true)
		ctrl.receive(nil, false, []uint32{}, true, true)
		ctrl.receive(nil, false, nil, false, true)
		require.Equal(t, crcs(spedFlight2), ctrl.acks)
	})

	t.Run("HandshakeCompleteKeepsPendingFlight", func(t *testing.T) {
		// M146: a DTLS 1.2 client or 1.3 server dropped its flight on
		// handshake completion.
		ctrl := pendingWithUnackedFlight(t)
		require.Equal(t, spedFlight3, ctrl.dataToPiggyback())
	})

	t.Run("NoEmptyData", func(t *testing.T) {
		// pion/ice v5 sends an empty DATA while confirmed with nothing to send.
		var ctrl spedController
		ctrl.arm()
		ctrl.receive(nil, false, []uint32{}, true, true)
		require.Equal(t, SPEDStateConfirmed, ctrl.state)
		require.Nil(t, ctrl.dataToPiggyback())
		acks, ok := ctrl.acksToPiggyback()
		require.True(t, ok)
		require.Empty(t, acks)
	})
}

func TestSPEDControllerStates(t *testing.T) {
	t.Run("Disabled", func(t *testing.T) {
		var ctrl spedController
		require.Equal(t, SPEDStateDisabled, ctrl.state)
		ctrl.capture([][]byte{spedFlight1})
		require.Nil(t, ctrl.dataToPiggyback())
		_, ok := ctrl.acksToPiggyback()
		require.False(t, ok)
		deliver, evaluate := ctrl.receive(spedFlight2, true, nil, false, true)
		require.False(t, deliver)
		require.False(t, evaluate)
		require.False(t, ctrl.reportDTLSPacket(spedFlight2))
		ctrl.handshakeComplete()
		require.False(t, ctrl.applicationDataReceived())
		require.False(t, ctrl.failed())
		require.Equal(t, SPEDStateDisabled, ctrl.state)
	})

	t.Run("ArmOnlyFromDisabled", func(t *testing.T) {
		var ctrl spedController
		ctrl.arm()
		require.Equal(t, SPEDStateTentative, ctrl.state)
		ctrl.failed()
		ctrl.arm()
		require.Equal(t, SPEDStateOff, ctrl.state)
	})

	t.Run("TentativeToConfirmedOnEitherAttribute", func(t *testing.T) {
		for name, msg := range map[string]struct {
			data    []byte
			hasData bool
			acks    []uint32
			hasAcks bool
		}{
			"EmptyAck":        {hasAcks: true, acks: []uint32{}},
			"Ack":             {hasAcks: true, acks: crcs(spedFlight1)},
			"EmptyData":       {hasData: true, data: []byte{}},
			"Data":            {hasData: true, data: spedFlight1},
			"NonDTLSData":     {hasData: true, data: []byte{1, 2, 3}},
			"DataAndEmptyAck": {hasData: true, data: spedFlight1, hasAcks: true, acks: []uint32{}},
		} {
			t.Run(name, func(t *testing.T) {
				var ctrl spedController
				ctrl.arm()
				ctrl.receive(msg.data, msg.hasData, msg.acks, msg.hasAcks, true)
				require.Equal(t, SPEDStateConfirmed, ctrl.state)
			})
		}
	})

	t.Run("ConfirmedIgnoresMessageWithoutAttributes", func(t *testing.T) {
		var ctrl spedController
		ctrl.arm()
		ctrl.receive(nil, false, []uint32{}, true, true)
		ctrl.receive(nil, false, nil, false, true)
		require.Equal(t, SPEDStateConfirmed, ctrl.state)
	})

	t.Run("TentativeToPendingOnHandshakeComplete", func(t *testing.T) {
		var ctrl spedController
		ctrl.arm()
		ctrl.handshakeComplete()
		require.Equal(t, SPEDStatePending, ctrl.state)
	})

	t.Run("PendingWithNothingOutstandingCompletesOnNextMessage", func(t *testing.T) {
		var ctrl spedController
		ctrl.arm()
		ctrl.receive(nil, false, []uint32{}, true, true)
		ctrl.handshakeComplete()
		// As in libwebrtc, completion is only evaluated on a received message.
		require.Equal(t, SPEDStatePending, ctrl.state)
		_, evaluate := ctrl.receive(nil, false, nil, false, true)
		require.True(t, evaluate)
		require.True(t, ctrl.evaluateCompletion())
		require.Equal(t, SPEDStateComplete, ctrl.state)
	})

	t.Run("CompleteIgnoresEverything", func(t *testing.T) {
		var ctrl spedController
		ctrl.arm()
		ctrl.handshakeComplete()
		require.True(t, ctrl.applicationDataReceived())
		require.Equal(t, SPEDStateComplete, ctrl.state)
		require.Nil(t, ctrl.acks)

		ctrl.capture([][]byte{spedFlight1})
		require.Nil(t, ctrl.dataToPiggyback())
		_, ok := ctrl.acksToPiggyback()
		require.False(t, ok)
		deliver, evaluate := ctrl.receive(spedFlight2, true, crcs(spedFlight1), true, true)
		require.False(t, deliver)
		require.False(t, evaluate)
		require.False(t, ctrl.reportDTLSPacket(spedFlight2))
		ctrl.handshakeComplete()
		require.False(t, ctrl.applicationDataReceived())
		require.Equal(t, SPEDStateComplete, ctrl.state)
		// The flight is held to be sent directly.
		require.Len(t, ctrl.takePending(), 1)
	})

	t.Run("ApplicationDataCompletesWithFlightOutstanding", func(t *testing.T) {
		ctrl := spedController{}
		ctrl.arm()
		ctrl.capture([][]byte{spedFlight3})
		ctrl.handshakeComplete()
		require.True(t, ctrl.applicationDataReceived())
		require.Equal(t, SPEDStateComplete, ctrl.state)
		// The unacknowledged flight stays available to be sent directly.
		require.Equal(t, []spedPacket{{data: spedFlight3, crc: crc32.ChecksumIEEE(spedFlight3)}}, ctrl.takePending())
		require.Empty(t, ctrl.pending)
	})

	t.Run("FailedDropsFlight", func(t *testing.T) {
		for _, state := range []SPEDState{SPEDStateTentative, SPEDStateConfirmed, SPEDStatePending, SPEDStateComplete} {
			ctrl := spedController{}
			ctrl.arm()
			ctrl.capture([][]byte{spedFlight1})
			ctrl.state = state
			require.True(t, ctrl.failed(), state.String())
			require.Equal(t, SPEDStateOff, ctrl.state)
			require.Empty(t, ctrl.pending)
			require.False(t, ctrl.failed())
		}
	})

	t.Run("NoCallbackNoAck", func(t *testing.T) {
		var ctrl spedController
		ctrl.arm()
		deliver, evaluate := ctrl.receive(spedFlight1, true, []uint32{}, true, false)
		require.False(t, deliver)
		require.True(t, evaluate)
		require.Empty(t, ctrl.acks)
		require.Zero(t, ctrl.dataReceived)
	})

	t.Run("Capture", func(t *testing.T) {
		var ctrl spedController
		ctrl.arm()
		flight := [][]byte{append([]byte{}, spedFlight1...), []byte("not dtls"), append([]byte{}, spedFlight2...)}
		ctrl.capture(flight)
		require.Len(t, ctrl.pending, 2)

		// The datagrams are copied.
		flight[0][0] = 0
		require.Equal(t, spedFlight1, ctrl.dataToPiggyback())

		// A flight without any DTLS datagram does not replace the pending one.
		ctrl.capture([][]byte{[]byte("not dtls")})
		ctrl.capture(nil)
		require.Len(t, ctrl.pending, 2)

		// A new flight replaces the pending one and restarts the round robin.
		ctrl.capture([][]byte{spedFlight3})
		require.Equal(t, spedFlight3, ctrl.dataToPiggyback())
		require.Equal(t, spedFlight3, ctrl.dataToPiggyback())
	})

	t.Run("String", func(t *testing.T) {
		for state, name := range map[SPEDState]string{
			SPEDStateDisabled:  "disabled",
			SPEDStateTentative: "tentative",
			SPEDStateConfirmed: "confirmed",
			SPEDStatePending:   "pending",
			SPEDStateComplete:  "complete",
			SPEDStateOff:       "off",
			SPEDState(42):      ErrUnknownType.Error(),
		} {
			require.Equal(t, name, state.String())
		}
	})
}

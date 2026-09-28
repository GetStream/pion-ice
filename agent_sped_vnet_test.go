// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5/test"
	"github.com/pion/transport/v5/vnet"
	"github.com/stretchr/testify/require"
)

// spedFakeDTLS stands in for a DTLS stack driven synchronously from the SPED
// callback: it records the datagrams it receives and answers once it has a
// whole flight.
type spedFakeDTLS struct {
	mu       sync.Mutex
	received map[string]int
	answered map[string]bool
}

func newSPEDFakeDTLS() *spedFakeDTLS {
	return &spedFakeDTLS{received: map[string]int{}, answered: map[string]bool{}}
}

func (d *spedFakeDTLS) receive(packet []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.received[string(packet)]++
}

// once reports, the first time only, whether every datagram of flight was
// received.
func (d *spedFakeDTLS) once(name string, flight [][]byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.answered[name] {
		return false
	}
	for _, datagram := range flight {
		if d.received[string(datagram)] == 0 {
			return false
		}
	}
	d.answered[name] = true

	return true
}

func (d *spedFakeDTLS) got(packet []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.received[string(packet)] > 0
}

type spedVNetAgents struct {
	full, lite *Agent
	virtualNet *virtualNet
}

// newSPEDVNetAgents creates a full agent behind a NAT and a lite agent with a
// public address. The caller defers close.
func newSPEDVNetAgents(t *testing.T) *spedVNetAgents {
	t.Helper()

	virtualNet, err := buildVNet(
		&vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointIndependent},
		&vnet.NATType{Mode: vnet.NATModeNAT1To1},
	)
	require.NoError(t, err)

	full, err := NewAgent(&AgentConfig{
		Urls: []*stun.URI{{
			Scheme: SchemeTypeSTUN, Host: vnetSTUNServerIP, Port: vnetSTUNServerPort, Proto: stun.ProtoTypeUDP,
		}},
		NetworkTypes:     supportedNetworkTypes(),
		MulticastDNSMode: MulticastDNSModeDisabled,
		Net:              virtualNet.net0,
	})
	require.NoError(t, err)

	lite, err := NewAgent(&AgentConfig{
		Lite:             true,
		CandidateTypes:   []CandidateType{CandidateTypeHost},
		NetworkTypes:     supportedNetworkTypes(),
		MulticastDNSMode: MulticastDNSModeDisabled,
		Net:              virtualNet.net1,
		NAT1To1IPs:       []string{vnetGlobalIPB},
	})
	require.NoError(t, err)

	return &spedVNetAgents{full: full, lite: lite, virtualNet: virtualNet}
}

func (s *spedVNetAgents) close(t *testing.T) {
	t.Helper()

	require.NoError(t, s.full.Close())
	require.NoError(t, s.lite.Close())
	s.virtualNet.close()
}

// start exchanges candidates and starts both agents without waiting.
func (s *spedVNetAgents) start(t *testing.T) (fullConn, liteConn *Conn) {
	t.Helper()

	fullUfrag, fullPwd, err := s.full.GetLocalUserCredentials()
	require.NoError(t, err)
	liteUfrag, litePwd, err := s.lite.GetLocalUserCredentials()
	require.NoError(t, err)
	gatherAndExchangeCandidates(t, s.full, s.lite)

	liteConn, err = s.lite.StartAccept(fullUfrag, fullPwd)
	require.NoError(t, err)
	fullConn, err = s.full.StartDial(liteUfrag, litePwd)
	require.NoError(t, err)

	return fullConn, liteConn
}

func spedPacketsSent(agent *Agent) uint32 {
	var sent uint32
	for _, stats := range agent.GetCandidatePairsStats() {
		sent += stats.PacketsSent
	}

	return sent
}

func spedPendingLen(agent *Agent) int {
	agent.sped.mu.Lock()
	defer agent.sped.mu.Unlock()

	return len(agent.sped.ctrl.pending)
}

// readDatagram reads datagrams from conn until want arrives.
func readDatagram(t *testing.T, conn *Conn, want []byte) {
	t.Helper()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		require.NoError(t, err)
		if string(buf[:n]) == string(want) {
			return
		}
	}
}

// TestSPEDLiteAndFull runs a simulated DTLS 1.3 handshake with a post-quantum
// ClientHello in two datagrams between a full agent (ICE controlling, DTLS
// client) and a lite agent (ICE controlled, DTLS server), inside STUN. The
// only DTLS that may be written directly is the second ClientHello datagram:
// the full agent flushes it when its first check is answered, unless a second
// check already carried it.
func TestSPEDLiteAndFull(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(30 * time.Second).Stop()

	clientHello := [][]byte{spedDatagram(850, 0xc1), spedDatagram(850, 0xc2)}
	serverFlight := [][]byte{spedDatagram(700, 0x51), spedDatagram(600, 0x52)}
	clientFinished := [][]byte{spedDatagram(80, 0xf1)}

	agents := newSPEDVNetAgents(t)
	defer agents.close(t)
	client, server := newSPEDFakeDTLS(), newSPEDFakeDTLS()

	require.NoError(t, agents.full.EnableSPED())
	agents.full.SetDTLSCallback(func(packet []byte, _ net.Addr) {
		client.receive(packet)
		if client.once("server flight", serverFlight) {
			require.True(t, agents.full.Piggyback(clientFinished))
			agents.full.SetDTLSHandshakeComplete()
		}
	})
	require.True(t, agents.full.Piggyback(clientHello))

	require.NoError(t, agents.lite.EnableSPED())
	agents.lite.SetDTLSCallback(func(packet []byte, _ net.Addr) {
		server.receive(packet)
		if server.once("client hello", clientHello) {
			require.True(t, agents.lite.Piggyback(serverFlight))
		}
		if server.once("client finished", clientFinished) {
			agents.lite.SetDTLSHandshakeComplete()
		}
	})

	agents.start(t)

	require.Eventually(t, func() bool {
		return agents.full.SPEDState() == SPEDStateComplete && agents.lite.SPEDState() == SPEDStateComplete
	}, 10*time.Second, 5*time.Millisecond)

	for _, datagram := range append(append([][]byte{}, clientHello...), clientFinished...) {
		require.True(t, server.got(datagram))
	}
	for _, datagram := range serverFlight {
		require.True(t, client.got(datagram))
	}

	// Completed by acknowledgements, with nothing left to send directly.
	require.Zero(t, spedPendingLen(agents.full))
	require.Zero(t, spedPendingLen(agents.lite))
	require.LessOrEqual(t, spedPacketsSent(agents.full), uint32(1))
	require.Zero(t, spedPacketsSent(agents.lite))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, agents.full.AwaitConnect(ctx))
	require.NoError(t, agents.lite.AwaitConnect(ctx))
}

// TestSPEDFlushOnFirstUsablePair checks that the datagrams still pending when
// a pair first becomes usable are sent directly on it, as libwebrtc does when
// ICE first becomes writable. The peers set no DTLS callback, so embedded
// datagrams are not delivered, and a datagram can only reach the peer's Conn
// directly.
func TestSPEDFlushOnFirstUsablePair(t *testing.T) {
	t.Run("Full", func(t *testing.T) {
		defer test.CheckRoutines(t)()
		defer test.TimeOut(30 * time.Second).Stop()

		// The checks sent before the first response carry, and implicitly
		// acknowledge, the first datagrams; the flush sends the rest.
		var flight [][]byte
		for i := range 6 {
			flight = append(flight, spedDatagram(100, byte(0xa0+i)))
		}
		agents := newSPEDVNetAgents(t)
		defer agents.close(t)
		require.NoError(t, agents.full.EnableSPED())
		require.NoError(t, agents.lite.EnableSPED())
		require.True(t, agents.full.Piggyback(flight))

		_, liteConn := agents.start(t)
		readDatagram(t, liteConn, flight[len(flight)-1])
		require.Equal(t, SPEDStateConfirmed, agents.full.SPEDState())
	})

	t.Run("Lite", func(t *testing.T) {
		defer test.CheckRoutines(t)()
		defer test.TimeOut(30 * time.Second).Stop()

		// The first check arrives before any datagram was sent, so the whole
		// flight is flushed.
		flight := [][]byte{spedDatagram(300, 0xa1), spedDatagram(300, 0xa2)}
		agents := newSPEDVNetAgents(t)
		defer agents.close(t)
		require.NoError(t, agents.full.EnableSPED())
		require.NoError(t, agents.lite.EnableSPED())
		require.True(t, agents.lite.Piggyback(flight))

		fullConn, _ := agents.start(t)
		for _, datagram := range flight {
			readDatagram(t, fullConn, datagram)
		}
		require.Equal(t, SPEDStateConfirmed, agents.lite.SPEDState())
	})
}

// TestSPEDFallback connects an agent with SPED to one without: SPED turns off
// on the first message from the peer, and the pending flight is sent directly
// once a pair is selected.
func TestSPEDFallback(t *testing.T) {
	flight := spedDatagram(300, 0xab)

	t.Run("FullWithSPED", func(t *testing.T) {
		defer test.CheckRoutines(t)()
		defer test.TimeOut(30 * time.Second).Stop()

		agents := newSPEDVNetAgents(t)
		defer agents.close(t)
		require.NoError(t, agents.full.EnableSPED())
		require.True(t, agents.full.Piggyback([][]byte{flight}))

		_, liteConn := agents.start(t)
		readDatagram(t, liteConn, flight)

		require.Equal(t, SPEDStateOff, agents.full.SPEDState())
		require.Equal(t, SPEDStateDisabled, agents.lite.SPEDState())
		require.Zero(t, spedPendingLen(agents.full))
		// Flights after the fallback are the caller's to send.
		require.False(t, agents.full.Piggyback([][]byte{flight}))
	})

	t.Run("LiteWithSPED", func(t *testing.T) {
		defer test.CheckRoutines(t)()
		defer test.TimeOut(30 * time.Second).Stop()

		agents := newSPEDVNetAgents(t)
		defer agents.close(t)
		require.NoError(t, agents.lite.EnableSPED())
		require.True(t, agents.lite.Piggyback([][]byte{flight}))

		fullConn, _ := agents.start(t)
		readDatagram(t, fullConn, flight)

		require.Equal(t, SPEDStateOff, agents.lite.SPEDState())
		require.Equal(t, SPEDStateDisabled, agents.full.SPEDState())
		require.Zero(t, spedPendingLen(agents.lite))
	})
}

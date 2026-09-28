// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"context"
	"hash/crc32"
	"net"
	"sync"
	"testing"

	"github.com/pion/ice/v4/internal/fakenet"
	"github.com/pion/stun/v4"
	"github.com/stretchr/testify/require"
)

const (
	spedTestRemoteUfrag = "remoteufrag"
	spedTestRemotePwd   = "remotepasswordremotepassword"
)

// spedRecordingConn records the datagrams a local candidate writes.
type spedRecordingConn struct {
	fakenet.MockPacketConn

	mu      sync.Mutex
	written [][]byte
}

func (c *spedRecordingConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, append([]byte{}, b...))

	return len(b), nil
}

// take returns and clears the recorded datagrams.
func (c *spedRecordingConn) take() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	written := c.written
	c.written = nil

	return written
}

// spedTestEnv is an agent with one local and one remote host candidate and
// the pair between them. Everything the local candidate writes is recorded.
type spedTestEnv struct {
	agent  *Agent
	local  *CandidateHost
	remote *CandidateHost
	conn   *spedRecordingConn
}

type spedTestConfig struct {
	controlling bool
	lite        bool
	disabled    bool
}

func newSPEDTestEnv(t *testing.T, cfg spedTestConfig) *spedTestEnv {
	t.Helper()

	agentConfig := &AgentConfig{
		MulticastDNSMode: MulticastDNSModeDisabled,
		NetworkTypes:     []NetworkType{NetworkTypeUDP4},
	}
	if cfg.lite {
		agentConfig.Lite = true
		agentConfig.CandidateTypes = []CandidateType{CandidateTypeHost}
	}
	agent, err := NewAgent(agentConfig)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, agent.Close()) })

	if !cfg.disabled {
		require.NoError(t, agent.EnableSPED())
	}

	local, err := NewCandidateHost(&CandidateHostConfig{Network: "udp", Address: "192.168.0.2", Port: 777, Component: 1})
	require.NoError(t, err)
	conn := &spedRecordingConn{}
	local.conn = conn

	remote, err := NewCandidateHost(&CandidateHostConfig{Network: "udp", Address: "172.17.0.3", Port: 999, Component: 1})
	require.NoError(t, err)

	env := &spedTestEnv{agent: agent, local: local, remote: remote, conn: conn}
	env.run(t, func() {
		agent.remoteUfrag = spedTestRemoteUfrag
		agent.remotePwd = spedTestRemotePwd
		agent.setRole(cfg.controlling)
		require.True(t, agent.addRemoteCandidate(remote))
		agent.addPair(local, remote)
	})

	return env
}

// run runs f on the agent's loop, as the agent's own handlers run.
func (e *spedTestEnv) run(t *testing.T, f func()) {
	t.Helper()

	require.NoError(t, e.agent.loop.Run(e.agent.loop, func(context.Context) { f() }))
}

// wire encodes and decodes msg as a received datagram.
func spedWire(t *testing.T, msg *stun.Message) *stun.Message {
	t.Helper()

	decoded := &stun.Message{Raw: append([]byte{}, msg.Raw...)}
	require.NoError(t, decoded.Decode())

	return decoded
}

// deliverRequest sends the agent an authenticated Binding request from the
// remote candidate, with extra attributes before MESSAGE-INTEGRITY.
func (e *spedTestEnv) deliverRequest(t *testing.T, extra ...stun.Setter) {
	t.Helper()

	var role stun.Setter = AttrControlling(1)
	if e.agent.isControlling.Load() {
		role = AttrControlled(1)
	}
	setters := []stun.Setter{
		stun.BindingRequest, stun.TransactionID,
		stun.NewUsername(e.agent.localUfrag + ":" + e.agent.remoteUfrag),
		role, PriorityAttr(e.remote.Priority()),
	}
	setters = append(setters, extra...)
	setters = append(setters, stun.NewShortTermIntegrity(e.agent.localPwd), stun.Fingerprint)
	msg, err := stun.Build(setters...)
	require.NoError(t, err)

	e.deliver(t, msg)
}

// deliverResponse answers request with a Binding success response from the
// remote candidate, with extra attributes before MESSAGE-INTEGRITY.
func (e *spedTestEnv) deliverResponse(t *testing.T, request *stun.Message, extra ...stun.Setter) {
	t.Helper()

	setters := []stun.Setter{
		request, stun.BindingSuccess,
		&stun.XORMappedAddress{IP: net.IPv4(192, 168, 0, 2), Port: 777},
	}
	setters = append(setters, extra...)
	setters = append(setters, stun.NewShortTermIntegrity(spedTestRemotePwd), stun.Fingerprint)
	msg, err := stun.Build(setters...)
	require.NoError(t, err)

	e.deliver(t, msg)
}

func (e *spedTestEnv) deliver(t *testing.T, msg *stun.Message) {
	t.Helper()

	decoded := spedWire(t, msg)
	e.run(t, func() { e.agent.handleInbound(decoded, e.local, e.remote.addrPort()) })
}

// ping discards what the agent wrote so far, has it send a connectivity
// check and returns it.
func (e *spedTestEnv) ping(t *testing.T) *stun.Message {
	t.Helper()

	e.conn.take()
	e.run(t, func() { e.agent.getSelector().PingCandidate(e.local, e.remote) })
	messages := e.stunMessages(t)
	require.Len(t, messages, 1)
	require.Equal(t, stun.BindingRequest, messages[0].Type)

	return messages[0]
}

// stunMessages returns the STUN messages written since the last call.
func (e *spedTestEnv) stunMessages(t *testing.T) []*stun.Message {
	t.Helper()

	var messages []*stun.Message
	for _, raw := range e.conn.take() {
		require.True(t, stun.IsMessage(raw))
		msg := &stun.Message{Raw: raw}
		require.NoError(t, msg.Decode())
		messages = append(messages, msg)
	}

	return messages
}

// response returns the only Binding success response written since the last
// call to stunMessages.
func (e *spedTestEnv) response(t *testing.T) *stun.Message {
	t.Helper()

	var response *stun.Message
	for _, msg := range e.stunMessages(t) {
		if msg.Type == stun.BindingSuccess {
			require.Nil(t, response)
			response = msg
		}
	}
	require.NotNil(t, response)

	return response
}

// attributeTypes lists the attribute types of msg in wire order.
func attributeTypes(msg *stun.Message) []stun.AttrType {
	types := make([]stun.AttrType, 0, len(msg.Attributes))
	for _, attr := range msg.Attributes {
		types = append(types, attr.Type)
	}

	return types
}

func spedDatagram(size int, fill byte) []byte {
	datagram := make([]byte, size)
	datagram[0] = 22 // DTLS handshake record.
	for i := dtlsRecordHeaderLen; i < size; i++ {
		datagram[i] = fill
	}

	return datagram
}

// TestSPEDDisabledWireIdentical checks that an agent without SPED builds every
// kind of Binding request and response exactly as pion/ice v4.4.4 does.
func TestSPEDDisabledWireIdentical(t *testing.T) { //nolint:maintidx
	type builder struct {
		name        string
		controlling bool
		send        func(env *spedTestEnv)
		expected    func(env *spedTestEnv, sent *stun.Message) []stun.Setter
	}
	builders := []builder{
		{
			name: "ControllingCheck", controlling: true,
			send: func(env *spedTestEnv) { env.agent.getSelector().PingCandidate(env.local, env.remote) },
			expected: func(env *spedTestEnv, sent *stun.Message) []stun.Setter {
				return []stun.Setter{
					stun.BindingRequest, stun.NewTransactionIDSetter(sent.TransactionID),
					stun.NewUsername(env.agent.remoteUfrag + ":" + env.agent.localUfrag),
					AttrControlling(env.agent.tieBreaker), PriorityAttr(env.local.Priority()),
					stun.NewShortTermIntegrity(env.agent.remotePwd), stun.Fingerprint,
				}
			},
		},
		{
			name: "ControlledCheck",
			send: func(env *spedTestEnv) { env.agent.getSelector().PingCandidate(env.local, env.remote) },
			expected: func(env *spedTestEnv, sent *stun.Message) []stun.Setter {
				return []stun.Setter{
					stun.BindingRequest, stun.NewTransactionIDSetter(sent.TransactionID),
					stun.NewUsername(env.agent.remoteUfrag + ":" + env.agent.localUfrag),
					AttrControlled(env.agent.tieBreaker), PriorityAttr(env.local.Priority()),
					stun.NewShortTermIntegrity(env.agent.remotePwd), stun.Fingerprint,
				}
			},
		},
		{
			name: "Nomination", controlling: true,
			send: func(env *spedTestEnv) {
				selector, ok := env.agent.getSelector().(*controllingSelector)
				if ok {
					selector.nominatePair(env.agent.findPair(env.local, env.remote))
				}
			},
			expected: func(env *spedTestEnv, sent *stun.Message) []stun.Setter {
				return []stun.Setter{
					stun.BindingRequest, stun.NewTransactionIDSetter(sent.TransactionID),
					stun.NewUsername(env.agent.remoteUfrag + ":" + env.agent.localUfrag),
					UseCandidate(), AttrControlling(env.agent.tieBreaker), PriorityAttr(env.local.Priority()),
					stun.NewShortTermIntegrity(env.agent.remotePwd), stun.Fingerprint,
				}
			},
		},
		{
			name: "Renomination", controlling: true,
			send: func(env *spedTestEnv) {
				env.agent.enableRenomination = true
				_ = env.agent.sendNominationRequest(env.agent.findPair(env.local, env.remote), 7)
			},
			expected: func(env *spedTestEnv, sent *stun.Message) []stun.Setter {
				return []stun.Setter{
					stun.BindingRequest, stun.NewTransactionIDSetter(sent.TransactionID),
					stun.NewUsername(env.agent.remoteUfrag + ":" + env.agent.localUfrag),
					UseCandidate(), AttrControlling(env.agent.tieBreaker), PriorityAttr(env.local.Priority()),
					NominationSetter{Value: 7, AttrType: env.agent.nominationAttribute},
					stun.NewShortTermIntegrity(env.agent.remotePwd), stun.Fingerprint,
				}
			},
		},
		{
			name: "SuccessResponse",
			send: func(env *spedTestEnv) {
				request, err := stun.Build(stun.BindingRequest, stun.TransactionID)
				if err == nil {
					env.agent.sendBindingSuccess(request, env.local, env.remote)
				}
			},
			expected: func(env *spedTestEnv, sent *stun.Message) []stun.Setter {
				return []stun.Setter{
					sent, stun.BindingSuccess,
					&stun.XORMappedAddress{IP: net.IPv4(172, 17, 0, 3).To4(), Port: 999},
					stun.NewShortTermIntegrity(env.agent.localPwd), stun.Fingerprint,
				}
			},
		},
	}

	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			env := newSPEDTestEnv(t, spedTestConfig{controlling: b.controlling, disabled: true})
			env.run(t, func() { b.send(env) })
			messages := env.stunMessages(t)
			require.Len(t, messages, 1)
			sent := messages[0]

			expected, err := stun.Build(b.expected(env, sent)...)
			require.NoError(t, err)
			require.Equal(t, expected.Raw, sent.Raw)
			require.Equal(t, SPEDStateDisabled, env.agent.SPEDState())
		})
	}

	t.Run("InboundAttributesIgnored", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{disabled: true})
		var delivered [][]byte
		env.agent.SetDTLSCallback(func(packet []byte, _ net.Addr) { delivered = append(delivered, packet) })
		env.deliverRequest(t, DtlsInStunAckAttribute{}, DtlsInStunAttribute(spedFlight1))

		response := env.response(t)
		require.NotContains(t, attributeTypes(response), stun.AttrDtlsInStunAck)
		require.NotContains(t, attributeTypes(response), stun.AttrDtlsInStun)
		require.Empty(t, delivered)
		require.Equal(t, SPEDStateDisabled, env.agent.SPEDState())
		require.False(t, env.agent.Piggyback([][]byte{spedFlight2}))
	})
}

func TestSPEDOutgoing(t *testing.T) {
	t.Run("EmptyAckWithoutPendingFlight", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.Equal(t, SPEDStateTentative, env.agent.SPEDState())

		request := env.ping(t)
		require.Equal(t, []stun.AttrType{
			stun.AttrUsername, stun.AttrICEControlling, stun.AttrPriority,
			stun.AttrDtlsInStunAck, stun.AttrMessageIntegrity, stun.AttrFingerprint,
		}, attributeTypes(request))
		ack, err := request.Get(stun.AttrDtlsInStunAck)
		require.NoError(t, err)
		require.Empty(t, ack)
	})

	t.Run("RoundRobinAcrossRequests", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight1, spedFlight2}))

		for _, expected := range [][]byte{spedFlight1, spedFlight2, spedFlight1} {
			request := env.ping(t)
			require.Equal(t, []stun.AttrType{
				stun.AttrUsername, stun.AttrICEControlling, stun.AttrPriority,
				stun.AttrDtlsInStunAck, stun.AttrDtlsInStun, stun.AttrMessageIntegrity, stun.AttrFingerprint,
			}, attributeTypes(request))
			attrs := spedAttributesFrom(request)
			require.Equal(t, expected, attrs.data)
			require.NoError(t, stun.NewShortTermIntegrity(spedTestRemotePwd).Check(request))
		}
	})

	t.Run("NominationAndRenomination", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight1}))

		env.run(t, func() {
			selector, ok := env.agent.getSelector().(*controllingSelector)
			require.True(t, ok)
			selector.nominatePair(env.agent.findPair(env.local, env.remote))
			env.agent.enableRenomination = true
			require.NoError(t, env.agent.sendNominationRequest(env.agent.findPair(env.local, env.remote), 3))
		})
		messages := env.stunMessages(t)
		require.Len(t, messages, 2)
		for _, msg := range messages {
			require.True(t, msg.Contains(stun.AttrUseCandidate))
			attrs := spedAttributesFrom(msg)
			require.True(t, attrs.hasAck)
			require.Equal(t, spedFlight1, attrs.data)
		}
	})

	t.Run("SizeBudget", func(t *testing.T) {
		// A message whose body already holds `body` bytes.
		messageWithBody := func(t *testing.T, body int) *stun.Message {
			t.Helper()

			msg := stun.New()
			msg.Type = stun.BindingRequest
			if body > 0 {
				msg.Add(stun.AttrSoftware, make([]byte, body-stunAttributeHeaderLen))
			}
			require.Equal(t, body, int(msg.Length))

			return msg
		}
		fourAcks := func() *spedSession {
			session := &spedSession{}
			session.ctrl.arm()
			for i := range 4 {
				session.ctrl.acknowledge(spedFakePacket(uint16(i))) //nolint:gosec // G115
			}

			return session
		}

		for _, tc := range []struct {
			name     string
			body     int
			datagram int
			ackLen   int // -1: no ACK attribute.
			data     bool
		}{
			{name: "Fits", body: 100, datagram: 900, ackLen: 16, data: true},
			{name: "ExactFit", body: 0, datagram: MaxSTUNBindingBody - 20 - 4, ackLen: 16, data: true},
			{name: "OneByteTooMany", body: 0, datagram: MaxSTUNBindingBody - 20 - 4 + 1, ackLen: 16},
			{name: "EmptyAckWhenFullAckDoesNotFit", body: MaxSTUNBindingBody - 16, datagram: 13, ackLen: 0},
			{name: "NothingWhenAckDoesNotFit", body: MaxSTUNBindingBody, datagram: 13, ackLen: -1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				session := fourAcks()
				session.ctrl.capture([][]byte{spedDatagram(tc.datagram, 1)})
				msg := messageWithBody(t, tc.body)
				require.NoError(t, spedSetter{session: session}.AddTo(msg))

				ack, err := msg.Get(stun.AttrDtlsInStunAck)
				if tc.ackLen < 0 {
					require.ErrorIs(t, err, stun.ErrAttributeNotFound)
				} else {
					require.NoError(t, err)
					require.Len(t, ack, tc.ackLen)
				}
				require.Equal(t, tc.data, msg.Contains(stun.AttrDtlsInStun))
				require.LessOrEqual(t, int(msg.Length), max(tc.body, MaxSTUNBindingBody))
			})
		}
	})

	t.Run("OversizedDatagramSkippedRoundRobin", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		small := spedDatagram(200, 2)
		require.True(t, env.agent.Piggyback([][]byte{spedDatagram(1200, 1), small}))

		// The first datagram does not fit and is skipped; the next one rides.
		require.False(t, env.ping(t).Contains(stun.AttrDtlsInStun))
		require.Equal(t, small, spedAttributesFrom(env.ping(t)).data)
	})
}

func TestSPEDInboundRequest(t *testing.T) {
	for _, lite := range []bool{false, true} {
		name := "Full"
		if lite {
			name = "Lite"
		}
		t.Run(name+"/FlightQueuedInCallbackRidesResponse", func(t *testing.T) {
			env := newSPEDTestEnv(t, spedTestConfig{lite: lite})
			var delivered [][]byte
			env.agent.SetDTLSCallback(func(packet []byte, rAddr net.Addr) {
				require.Equal(t, env.remote.addr().String(), rAddr.String())
				delivered = append(delivered, append([]byte{}, packet...))
				require.True(t, env.agent.Piggyback([][]byte{spedFlight2}))
			})

			env.deliverRequest(t, DtlsInStunAckAttribute{}, DtlsInStunAttribute(spedFlight1))
			require.Equal(t, [][]byte{spedFlight1}, delivered)
			require.Equal(t, SPEDStateConfirmed, env.agent.SPEDState())

			attrs := spedAttributesFrom(env.response(t))
			require.Equal(t, crcs(spedFlight1), attrs.acks)
			require.Equal(t, spedFlight2, attrs.data)
		})
	}

	t.Run("WithoutAttributesTurnsOff", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{lite: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight2}))

		env.deliverRequest(t)
		require.Equal(t, SPEDStateOff, env.agent.SPEDState())
		// The response to that request already carries no SPED attribute.
		response := env.response(t)
		require.False(t, response.Contains(stun.AttrDtlsInStunAck))
		require.False(t, response.Contains(stun.AttrDtlsInStun))
	})

	t.Run("AttributesAfterMessageIntegrityIgnored", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{lite: true})
		var delivered int
		env.agent.SetDTLSCallback(func([]byte, net.Addr) { delivered++ })

		msg, err := stun.Build(stun.BindingRequest, stun.TransactionID,
			stun.NewUsername(env.agent.localUfrag+":"+env.agent.remoteUfrag),
			AttrControlling(1), PriorityAttr(env.remote.Priority()),
			stun.NewShortTermIntegrity(env.agent.localPwd))
		require.NoError(t, err)
		msg.Add(stun.AttrDtlsInStunAck, nil)
		msg.Add(stun.AttrDtlsInStun, spedFlight1)
		msg.WriteLength()
		require.NoError(t, stun.Fingerprint.AddTo(msg))

		env.deliver(t, msg)
		require.Zero(t, delivered)
		require.Equal(t, SPEDStateOff, env.agent.SPEDState())
	})

	t.Run("NonDTLSDataDropped", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{lite: true})
		var delivered int
		env.agent.SetDTLSCallback(func([]byte, net.Addr) { delivered++ })

		env.deliverRequest(t, DtlsInStunAckAttribute{}, DtlsInStunAttribute("not a DTLS record"))
		require.Zero(t, delivered)
		require.Equal(t, SPEDStateConfirmed, env.agent.SPEDState())
		require.Empty(t, spedAttributesFrom(env.response(t)).acks)
	})

	t.Run("WithoutCallbackNotAcknowledged", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{lite: true})

		env.deliverRequest(t, DtlsInStunAttribute(spedFlight1))
		require.Equal(t, SPEDStateConfirmed, env.agent.SPEDState())
		attrs := spedAttributesFrom(env.response(t))
		require.True(t, attrs.hasAck)
		require.Empty(t, attrs.acks)
	})

	t.Run("MalformedAckAloneTurnsOff", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{lite: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight2}))

		// A malformed ACK is no ACK: this request carries nothing usable.
		env.deliverRequest(t, spedRawAttribute{stun.AttrDtlsInStunAck, []byte{1, 2, 3}})
		require.Equal(t, SPEDStateOff, env.agent.SPEDState())
	})
}

// spedRawAttribute adds an attribute with an arbitrary value.
type spedRawAttribute struct {
	attrType stun.AttrType
	value    []byte
}

func (r spedRawAttribute) AddTo(m *stun.Message) error {
	m.Add(r.attrType, r.value)

	return nil
}

func TestSPEDInboundResponse(t *testing.T) {
	t.Run("ImplicitAck", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight1}))
		request := env.ping(t)

		// An empty ACK in the response acknowledges the request's DATA.
		env.deliverResponse(t, request, DtlsInStunAckAttribute{})
		require.Equal(t, SPEDStateConfirmed, env.agent.SPEDState())
		require.False(t, env.ping(t).Contains(stun.AttrDtlsInStun))
	})

	t.Run("ImplicitAckWithMalformedAck", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight1}))
		request := env.ping(t)

		env.deliverResponse(t, request, spedRawAttribute{stun.AttrDtlsInStunAck, []byte{1}})
		require.Equal(t, SPEDStateConfirmed, env.agent.SPEDState())
		require.False(t, env.ping(t).Contains(stun.AttrDtlsInStun))
	})

	t.Run("NoImplicitAckWithoutAckAttribute", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight1}))
		request := env.ping(t)

		env.deliverResponse(t, request, DtlsInStunAttribute(spedFlight2))
		require.Equal(t, SPEDStateConfirmed, env.agent.SPEDState())
		require.Equal(t, spedFlight1, spedAttributesFrom(env.ping(t)).data)
	})

	t.Run("ExplicitAck", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight1, spedFlight2}))
		env.ping(t)
		request := env.ping(t)

		env.deliverResponse(t, request, DtlsInStunAckAttribute(crcs(spedFlight1)))
		// Flight 2 went out in that request and is implicitly acknowledged.
		require.False(t, env.ping(t).Contains(stun.AttrDtlsInStun))
	})

	t.Run("DataDeliveredAndAcknowledged", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		var delivered [][]byte
		env.agent.SetDTLSCallback(func(packet []byte, _ net.Addr) { delivered = append(delivered, packet) })
		request := env.ping(t)

		env.deliverResponse(t, request, DtlsInStunAckAttribute{}, DtlsInStunAttribute(spedFlight2))
		require.Equal(t, [][]byte{spedFlight2}, delivered)
		require.Equal(t, crcs(spedFlight2), spedAttributesFrom(env.ping(t)).acks)
	})

	t.Run("WithoutAttributesTurnsOff", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight1}))
		request := env.ping(t)

		env.deliverResponse(t, request)
		require.Equal(t, SPEDStateOff, env.agent.SPEDState())
		request = env.ping(t)
		require.False(t, request.Contains(stun.AttrDtlsInStunAck))
		require.False(t, request.Contains(stun.AttrDtlsInStun))
	})

	t.Run("IgnoredWhenRequestCarriedNoAttributes", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true, disabled: true})
		request := env.ping(t)
		require.False(t, request.Contains(stun.AttrDtlsInStunAck))

		// Only possible when SPED is enabled while a check is in flight.
		require.NoError(t, env.agent.EnableSPED())
		env.deliverResponse(t, request)
		require.Equal(t, SPEDStateTentative, env.agent.SPEDState())
	})
}

func TestSPEDDirectPackets(t *testing.T) {
	t.Run("ReportDTLSPacketAcknowledged", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		env.agent.ReportDTLSPacket(spedFlight2)
		env.agent.ReportDTLSPacket([]byte("not DTLS"))
		env.agent.ReportDTLSPacket(spedFlight2)
		require.Equal(t, crcs(spedFlight2), spedAttributesFrom(env.ping(t)).acks)
	})

	t.Run("ReportDTLSPacketIgnoredWhenDisabled", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true, disabled: true})
		env.agent.ReportDTLSPacket(spedFlight2)
		require.False(t, env.ping(t).Contains(stun.AttrDtlsInStunAck))
	})
}

func TestSPEDCompletion(t *testing.T) {
	t.Run("AckedLastFlightCompletes", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight3}))
		env.agent.SetDTLSHandshakeComplete()
		require.Equal(t, SPEDStatePending, env.agent.SPEDState())

		// A message without DATA and without an ACK of the last flight does not
		// complete (M146 did).
		env.deliverRequest(t, DtlsInStunAckAttribute{})
		env.deliverRequest(t)
		require.Equal(t, SPEDStatePending, env.agent.SPEDState())

		env.deliverRequest(t, DtlsInStunAckAttribute(crcs(spedFlight3)))
		require.Equal(t, SPEDStateComplete, env.agent.SPEDState())

		// No SPED attribute any more.
		request := env.ping(t)
		require.False(t, request.Contains(stun.AttrDtlsInStunAck))
		// Complete without a selected pair: the flight is held for it.
		require.True(t, env.agent.Piggyback([][]byte{spedFlight4}))
	})

	t.Run("ApplicationDataFlushesOnSelectedPair", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		env.run(t, func() { env.agent.setSelectedPair(env.agent.findPair(env.local, env.remote)) })
		env.conn.take()

		require.True(t, env.agent.Piggyback([][]byte{spedFlight3, spedFlight4}))
		env.agent.ApplicationDataReceived() // Not PENDING yet: ignored.
		require.Equal(t, SPEDStateTentative, env.agent.SPEDState())
		env.agent.SetDTLSHandshakeComplete()
		env.agent.ApplicationDataReceived()
		require.Equal(t, SPEDStateComplete, env.agent.SPEDState())
		require.Equal(t, [][]byte{spedFlight3, spedFlight4}, env.conn.take())

		// Complete with a selected pair: the caller sends flights itself.
		require.False(t, env.agent.Piggyback([][]byte{spedFlight4}))
		env.agent.ApplicationDataReceived()
		require.Empty(t, env.conn.take())
	})

	t.Run("FallbackHoldsFlightUntilPairSelected", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight1}))
		request := env.ping(t)
		env.deliverResponse(t, request)
		require.Equal(t, SPEDStateOff, env.agent.SPEDState())
		require.Empty(t, env.conn.take())

		// A flight produced after the fallback replaces the held one.
		require.True(t, env.agent.Piggyback([][]byte{spedFlight3}))

		env.run(t, func() { env.agent.setSelectedPair(env.agent.findPair(env.local, env.remote)) })
		require.Equal(t, [][]byte{spedFlight3}, env.conn.take())

		require.False(t, env.agent.Piggyback([][]byte{spedFlight4}))
	})

	t.Run("FallbackFlushesOnSelectedPair", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{lite: true})
		env.run(t, func() { env.agent.setSelectedPair(env.agent.findPair(env.local, env.remote)) })
		env.conn.take()
		require.True(t, env.agent.Piggyback([][]byte{spedFlight2}))

		env.deliverRequest(t)
		require.Equal(t, SPEDStateOff, env.agent.SPEDState())
		written := env.conn.take()
		require.Equal(t, spedFlight2, written[0])
		require.True(t, stun.IsMessage(written[1]))
	})

	t.Run("FailedDropsFlight", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		require.True(t, env.agent.Piggyback([][]byte{spedFlight1}))
		env.agent.SetDTLSFailed()
		require.Equal(t, SPEDStateOff, env.agent.SPEDState())
		require.False(t, env.ping(t).Contains(stun.AttrDtlsInStunAck))

		env.run(t, func() { env.agent.setSelectedPair(env.agent.findPair(env.local, env.remote)) })
		for _, written := range env.conn.take() {
			require.True(t, stun.IsMessage(written))
		}
	})
}

func TestSPEDEnable(t *testing.T) {
	t.Run("Idempotent", func(t *testing.T) {
		agent, err := NewAgent(&AgentConfig{})
		require.NoError(t, err)
		defer func() { require.NoError(t, agent.Close()) }()

		require.Equal(t, SPEDStateDisabled, agent.SPEDState())
		require.NoError(t, agent.EnableSPED())
		require.NoError(t, agent.EnableSPED())
		require.Equal(t, SPEDStateTentative, agent.SPEDState())
		agent.SetDTLSFailed()
		require.NoError(t, agent.EnableSPED())
		require.Equal(t, SPEDStateOff, agent.SPEDState())
	})

	t.Run("AfterStart", func(t *testing.T) {
		agent, err := NewAgent(&AgentConfig{})
		require.NoError(t, err)
		defer func() { require.NoError(t, agent.Close()) }()

		_, err = agent.StartDial(spedTestRemoteUfrag, spedTestRemotePwd)
		require.NoError(t, err)
		require.ErrorIs(t, agent.EnableSPED(), ErrSPEDAfterStart)
		require.Equal(t, SPEDStateDisabled, agent.SPEDState())
	})

	t.Run("AfterClose", func(t *testing.T) {
		agent, err := NewAgent(&AgentConfig{})
		require.NoError(t, err)
		require.NoError(t, agent.Close())
		require.ErrorIs(t, agent.EnableSPED(), ErrClosed)
	})
}

func TestSPEDRequestRecordsSentAttributes(t *testing.T) {
	env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
	require.True(t, env.agent.Piggyback([][]byte{spedFlight1}))
	env.ping(t)
	env.run(t, func() {
		require.Len(t, env.agent.pendingBindingRequests, 1)
		request := env.agent.pendingBindingRequests[0]
		require.True(t, request.spedSent)
		require.True(t, request.spedDataSent)
		require.Equal(t, crc32.ChecksumIEEE(spedFlight1), request.spedDataCRC)
	})
}

func TestSPEDWriteDTLS(t *testing.T) {
	t.Run("LiteAfterAuthenticatedRequest", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{lite: true})
		_, err := env.agent.WriteDTLS(spedFlight2)
		require.ErrorIs(t, err, ErrNoCandidatePairs)

		// The DTLS server answers the ClientHello from the callback: directly,
		// then in the response.
		env.agent.SetDTLSCallback(func([]byte, net.Addr) {
			require.True(t, env.agent.Piggyback([][]byte{spedFlight2}))
			n, err := env.agent.WriteDTLS(spedFlight2)
			require.NoError(t, err)
			require.Len(t, spedFlight2, n)
		})
		env.deliverRequest(t, DtlsInStunAckAttribute{}, DtlsInStunAttribute(spedFlight1))
		require.Nil(t, env.agent.getSelectedPair())

		written := env.conn.take()
		require.Len(t, written, 2)
		require.Equal(t, spedFlight2, written[0])
		response := &stun.Message{Raw: written[1]}
		require.NoError(t, response.Decode())
		require.Equal(t, spedFlight2, spedAttributesFrom(response).data)
	})

	t.Run("LiteNotAfterFallback", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{lite: true})
		env.deliverRequest(t)
		require.Equal(t, SPEDStateOff, env.agent.SPEDState())

		_, err := env.agent.WriteDTLS(spedFlight2)
		require.ErrorIs(t, err, ErrNoCandidatePairs)
	})

	t.Run("FullAfterSuccessResponse", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		_, err := env.agent.WriteDTLS(spedFlight1)
		require.ErrorIs(t, err, ErrNoCandidatePairs)

		env.deliverResponse(t, env.ping(t), DtlsInStunAckAttribute{})
		env.conn.take()
		_, err = env.agent.WriteDTLS(spedFlight1)
		require.NoError(t, err)
		require.Equal(t, [][]byte{spedFlight1}, env.conn.take())
	})

	t.Run("SelectedPair", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true, disabled: true})
		env.run(t, func() { env.agent.setSelectedPair(env.agent.findPair(env.local, env.remote)) })
		env.conn.take()

		_, err := env.agent.WriteDTLS(spedFlight1)
		require.NoError(t, err)
		require.Equal(t, [][]byte{spedFlight1}, env.conn.take())
	})

	t.Run("ForgottenWhenPairsDropped", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{lite: true})
		env.deliverRequest(t, DtlsInStunAckAttribute{})
		_, err := env.agent.WriteDTLS(spedFlight2)
		require.NoError(t, err)

		env.run(t, func() { env.agent.setSelectedPair(nil) })
		_, err = env.agent.WriteDTLS(spedFlight2)
		require.ErrorIs(t, err, ErrNoCandidatePairs)
	})

	t.Run("RejectsSTUN", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{controlling: true})
		_, err := env.agent.WriteDTLS(env.ping(t).Raw)
		require.ErrorIs(t, err, errWriteSTUNMessageToIceConn)
	})

	t.Run("Closed", func(t *testing.T) {
		agent, err := NewAgent(&AgentConfig{})
		require.NoError(t, err)
		require.NoError(t, agent.Close())
		_, err = agent.WriteDTLS(spedFlight1)
		require.ErrorIs(t, err, ErrClosed)
	})

	t.Run("CompleteFlushesOnUsablePair", func(t *testing.T) {
		env := newSPEDTestEnv(t, spedTestConfig{lite: true})
		env.deliverRequest(t, DtlsInStunAckAttribute{})
		env.conn.take()

		require.True(t, env.agent.Piggyback([][]byte{spedFlight4}))
		env.agent.SetDTLSHandshakeComplete()
		env.agent.ApplicationDataReceived()
		require.Equal(t, SPEDStateComplete, env.agent.SPEDState())
		require.Nil(t, env.agent.getSelectedPair())
		require.Equal(t, [][]byte{spedFlight4}, env.conn.take())
	})
}

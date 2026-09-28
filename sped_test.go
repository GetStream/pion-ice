// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/pion/stun/v4"
	"github.com/stretchr/testify/require"
)

func TestDtlsInStunAttribute_GetFrom(t *testing.T) {
	m := new(stun.Message)
	var dtlsInStun DtlsInStunAttribute
	require.ErrorIs(t, stun.ErrAttributeNotFound, dtlsInStun.GetFrom(m))

	expectedValue := []byte{0x01, 0x02, 0x03, 0x04}
	m.Add(stun.AttrDtlsInStun, expectedValue)

	var dtlsInStun1 DtlsInStunAttribute
	require.NoError(t, dtlsInStun1.GetFrom(m))
	require.Equal(t, expectedValue, []byte(dtlsInStun1))
}

func TestDtlsInStunAttribute_AddTo(t *testing.T) {
	m := new(stun.Message)
	dtlsInStun := DtlsInStunAttribute([]byte{0x05, 0x06, 0x07, 0x08})
	require.NoError(t, dtlsInStun.AddTo(m))

	v, err := m.Get(stun.AttrDtlsInStun)
	require.NoError(t, err)
	require.Equal(t, []byte{0x05, 0x06, 0x07, 0x08}, v)
}

func TestDtlsInStunAckAttribute_GetFrom(t *testing.T) {
	m := new(stun.Message)
	var dtlsInStunAck DtlsInStunAckAttribute
	require.ErrorIs(t, stun.ErrAttributeNotFound, dtlsInStunAck.GetFrom(m))

	// Test with valid data
	expectedValue := []uint32{0x01020304, 0x05060708}
	byteValue := make([]byte, 8)
	binary.BigEndian.PutUint32(byteValue[0:4], expectedValue[0])
	binary.BigEndian.PutUint32(byteValue[4:8], expectedValue[1])
	m.Add(stun.AttrDtlsInStunAck, byteValue)

	var dtlsInStunAck1 DtlsInStunAckAttribute
	require.NoError(t, dtlsInStunAck1.GetFrom(m))
	require.Equal(t, expectedValue, []uint32(dtlsInStunAck1))

	// Test with the maximum valid size.
	m4 := new(stun.Message)
	maxValue := make([]byte, ackSizeBytes)
	m4.Add(stun.AttrDtlsInStunAck, maxValue)
	var dtlsInStunAck4 DtlsInStunAckAttribute
	require.NoError(t, dtlsInStunAck4.GetFrom(m4))
	require.Len(t, dtlsInStunAck4, ackSizeValues)

	// Test with invalid size (not multiple of 4)
	m2 := new(stun.Message)
	m2.Add(stun.AttrDtlsInStunAck, []byte{0x01, 0x02, 0x03})
	var dtlsInStunAck2 DtlsInStunAckAttribute
	require.ErrorIs(t, stun.ErrAttributeSizeInvalid, dtlsInStunAck2.GetFrom(m2))
	require.Empty(t, dtlsInStunAck2)

	// Test with invalid size (greater than ackSize)
	m3 := new(stun.Message)
	m3.Add(stun.AttrDtlsInStunAck, make([]byte, ackSizeBytes+4))
	var dtlsInStunAck3 DtlsInStunAckAttribute
	require.ErrorIs(t, stun.ErrAttributeSizeInvalid, dtlsInStunAck3.GetFrom(m3))
	require.Empty(t, dtlsInStunAck3)
}

func TestDtlsInStunAckAttribute_AddTo(t *testing.T) {
	m := new(stun.Message)
	dtlsInStunAck := DtlsInStunAckAttribute([]uint32{0x090a0b0c, 0x0d0e0f10})
	require.NoError(t, dtlsInStunAck.AddTo(m))

	v, err := m.Get(stun.AttrDtlsInStunAck)
	require.NoError(t, err)

	expectedByteValue := make([]byte, 8)
	binary.BigEndian.PutUint32(expectedByteValue[0:4], 0x090a0b0c)
	binary.BigEndian.PutUint32(expectedByteValue[4:8], 0x0d0e0f10)
	require.Equal(t, expectedByteValue, v)

	// Test with more than 4 elements (should not add to message)
	m2 := new(stun.Message)
	dtlsInStunAck2 := DtlsInStunAckAttribute([]uint32{1, 2, 3, 4, 5})
	require.ErrorIs(t, stun.ErrAttributeSizeInvalid, dtlsInStunAck2.AddTo(m2))
	_, err = m2.Get(stun.AttrDtlsInStunAck)
	require.ErrorIs(t, err, stun.ErrAttributeNotFound)
}

// spedWireVector is the Binding request of research/sped.md §2.2: USERNAME
// "RFRG:LFRG", PRIORITY, ICE-CONTROLLING, an ACK with one entry and a DATA
// carrying an 18-byte DTLS record, then MESSAGE-INTEGRITY with the remote
// password "remotepasswordremotepwd1" and FINGERPRINT.
const spedWireVector = "" +
	"00 01 00 64 21 12 a4 42 01 02 03 04 05 06 07 08" +
	"09 0a 0b 0c 00 06 00 09 52 46 52 47 3a 4c 46 52" +
	"47 00 00 00 00 24 00 04 6e 7f 1e ff 80 2a 00 08" +
	"00 00 00 00 00 00 00 00 c0 71 00 04 de ad be ef" +
	"c0 70 00 12 16 fe fd 00 00 00 00 00 00 00 00 00" +
	"05 01 00 00 00 00 00 00 00 08 00 14 fc bf 8d 57" +
	"fc 58 4a 1e 5b 02 20 fa a0 d9 2b db 06 f0 dc 9b" +
	"80 28 00 04 d8 84 73 74"

func spedWireVectorBytes(tb testing.TB) []byte {
	tb.Helper()

	raw, err := hex.DecodeString(strings.ReplaceAll(spedWireVector, " ", ""))
	require.NoError(tb, err)

	return raw
}

var spedWireVectorDTLS = []byte{ //nolint:gochecknoglobals
	0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
}

func TestSPEDWireVector(t *testing.T) {
	raw := spedWireVectorBytes(t)
	txID := [stun.TransactionIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	t.Run("Encode", func(t *testing.T) {
		msg, err := stun.Build(
			stun.BindingRequest,
			stun.NewTransactionIDSetter(txID),
			stun.NewUsername("RFRG:LFRG"),
			PriorityAttr(0x6e7f1eff),
			AttrControlling(0),
			DtlsInStunAckAttribute{0xdeadbeef},
			DtlsInStunAttribute(spedWireVectorDTLS),
			stun.NewShortTermIntegrity("remotepasswordremotepwd1"),
			stun.Fingerprint,
		)
		require.NoError(t, err)
		require.Equal(t, hex.EncodeToString(raw), hex.EncodeToString(msg.Raw))
	})

	t.Run("Decode", func(t *testing.T) {
		msg := &stun.Message{Raw: append([]byte{}, raw...)}
		require.NoError(t, msg.Decode())
		require.NoError(t, stun.NewShortTermIntegrity("remotepasswordremotepwd1").Check(msg))
		require.NoError(t, stun.Fingerprint.Check(msg))

		attrs := spedAttributesFrom(msg)
		require.True(t, attrs.hasData)
		require.Equal(t, spedWireVectorDTLS, attrs.data)
		require.True(t, isDTLSPacket(attrs.data))
		require.True(t, attrs.hasAck)
		require.True(t, attrs.ackValid)
		require.Equal(t, []uint32{0xdeadbeef}, attrs.acks)

		// The CRC a peer puts in its ACK for this datagram.
		require.Equal(t, uint32(0x3fa4766a), crc32.ChecksumIEEE(attrs.data))
	})
}

func TestSPEDAttributesFrom(t *testing.T) {
	t.Run("None", func(t *testing.T) {
		msg, err := stun.Build(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
		require.NoError(t, err)

		attrs := spedAttributesFrom(msg)
		require.False(t, attrs.hasData)
		require.False(t, attrs.hasAck)
	})

	t.Run("EmptyAckAndEmptyData", func(t *testing.T) {
		msg, err := stun.Build(stun.BindingRequest, stun.TransactionID,
			DtlsInStunAckAttribute{}, DtlsInStunAttribute{})
		require.NoError(t, err)

		attrs := spedAttributesFrom(msg)
		require.True(t, attrs.hasAck)
		require.True(t, attrs.ackValid)
		require.Empty(t, attrs.acks)
		require.True(t, attrs.hasData)
		require.Empty(t, attrs.data)
	})

	t.Run("AckLengthNotMultipleOfFour", func(t *testing.T) {
		for _, size := range []int{1, 2, 3, 5, 7, 17} {
			msg := new(stun.Message)
			msg.Add(stun.AttrDtlsInStunAck, make([]byte, size))

			attrs := spedAttributesFrom(msg)
			require.True(t, attrs.hasAck, "size %d", size)
			require.False(t, attrs.ackValid, "size %d", size)
			require.Nil(t, attrs.acks, "size %d", size)
		}
	})

	t.Run("AckWithMoreThanFourEntries", func(t *testing.T) {
		// libwebrtc never sends more than four, but accepts more.
		msg := new(stun.Message)
		value := make([]byte, 24)
		for i := range 6 {
			binary.BigEndian.PutUint32(value[i*4:], uint32(i+1)) //nolint:gosec // G115
		}
		msg.Add(stun.AttrDtlsInStunAck, value)

		attrs := spedAttributesFrom(msg)
		require.True(t, attrs.ackValid)
		require.Equal(t, []uint32{1, 2, 3, 4, 5, 6}, attrs.acks)
	})

	t.Run("FirstOccurrenceWins", func(t *testing.T) {
		msg := new(stun.Message)
		msg.Add(stun.AttrDtlsInStunAck, []byte{0, 0, 0, 1})
		msg.Add(stun.AttrDtlsInStun, spedWireVectorDTLS)
		msg.Add(stun.AttrDtlsInStunAck, []byte{0, 0, 0, 2})
		msg.Add(stun.AttrDtlsInStun, []byte{1})

		attrs := spedAttributesFrom(msg)
		require.Equal(t, []uint32{1}, attrs.acks)
		require.Equal(t, spedWireVectorDTLS, attrs.data)
	})

	for _, integrity := range []stun.AttrType{
		stun.AttrMessageIntegrity, stun.AttrMessageIntegritySHA256, stun.AttrFingerprint,
	} {
		t.Run("IgnoredAfter"+integrity.String(), func(t *testing.T) {
			// Attributes added after an integrity attribute, as an attacker
			// on path could append them to an authenticated message.
			msg := new(stun.Message)
			msg.Add(integrity, make([]byte, 20))
			msg.Add(stun.AttrDtlsInStunAck, []byte{0xde, 0xad, 0xbe, 0xef})
			msg.Add(stun.AttrDtlsInStun, spedWireVectorDTLS)

			attrs := spedAttributesFrom(msg)
			require.False(t, attrs.hasAck)
			require.False(t, attrs.hasData)
		})
	}

	t.Run("IgnoredAfterMessageIntegrityOnTheWire", func(t *testing.T) {
		// An authenticated request with ACK and DATA appended after
		// MESSAGE-INTEGRITY and a FINGERPRINT recomputed over them.
		msg, err := stun.Build(stun.BindingRequest, stun.TransactionID,
			stun.NewUsername("RFRG:LFRG"),
			stun.NewShortTermIntegrity("remotepasswordremotepwd1"))
		require.NoError(t, err)
		msg.Add(stun.AttrDtlsInStunAck, []byte{0xde, 0xad, 0xbe, 0xef})
		msg.Add(stun.AttrDtlsInStun, spedWireVectorDTLS)
		msg.WriteLength()
		require.NoError(t, stun.Fingerprint.AddTo(msg))

		decoded := &stun.Message{Raw: append([]byte{}, msg.Raw...)}
		require.NoError(t, decoded.Decode())
		require.NoError(t, stun.NewShortTermIntegrity("remotepasswordremotepwd1").Check(decoded))

		attrs := spedAttributesFrom(decoded)
		require.False(t, attrs.hasAck)
		require.False(t, attrs.hasData)
	})
}

func TestIsDTLSPacket(t *testing.T) {
	record := make([]byte, dtlsRecordHeaderLen)
	for first := range 256 {
		record[0] = byte(first)
		require.Equal(t, first >= 20 && first <= 63, isDTLSPacket(record), "first byte %d", first)
	}
	require.False(t, isDTLSPacket(spedWireVectorDTLS[:dtlsRecordHeaderLen-1]))
	require.False(t, isDTLSPacket(nil))
}

func FuzzSPEDAttributesFrom(f *testing.F) {
	f.Add(spedWireVectorBytes(f))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xc0, 0x71, 0x00, 0x03, 1, 2, 3, 0})

	f.Fuzz(func(t *testing.T, raw []byte) {
		msg := &stun.Message{Raw: append([]byte{}, raw...)}
		if msg.Decode() != nil {
			return
		}
		attrs := spedAttributesFrom(msg)

		beforeIntegrity := map[stun.AttrType][]byte{}
		for _, attr := range msg.Attributes {
			if attr.Type == stun.AttrMessageIntegrity || attr.Type == stun.AttrMessageIntegritySHA256 ||
				attr.Type == stun.AttrFingerprint {
				break
			}
			if _, ok := beforeIntegrity[attr.Type]; !ok {
				beforeIntegrity[attr.Type] = attr.Value
			}
		}

		data, ok := beforeIntegrity[stun.AttrDtlsInStun]
		require.Equal(t, ok, attrs.hasData)
		require.Equal(t, data, attrs.data)

		ack, ok := beforeIntegrity[stun.AttrDtlsInStunAck]
		require.Equal(t, ok, attrs.hasAck)
		require.Equal(t, ok && len(ack)%4 == 0, attrs.ackValid)
		if attrs.ackValid {
			require.Len(t, attrs.acks, len(ack)/4)
			for i, crc := range attrs.acks {
				require.Equal(t, binary.BigEndian.Uint32(ack[i*4:]), crc)
			}
		} else {
			require.Nil(t, attrs.acks)
		}
	})
}

func FuzzDtlsInStunAckAttribute(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xde, 0xad, 0xbe, 0xef})
	f.Add([]byte{1, 2, 3})
	f.Add(make([]byte, 20))

	f.Fuzz(func(t *testing.T, value []byte) {
		msg := new(stun.Message)
		msg.Add(stun.AttrDtlsInStunAck, value)

		var ack DtlsInStunAckAttribute
		if err := ack.GetFrom(msg); err != nil {
			require.ErrorIs(t, err, stun.ErrAttributeSizeInvalid)
			require.True(t, len(value)%4 != 0 || len(value) > ackSizeBytes)

			return
		}
		require.Len(t, ack, len(value)/4)

		// Round trip.
		encoded := new(stun.Message)
		require.NoError(t, ack.AddTo(encoded))
		got, err := encoded.Get(stun.AttrDtlsInStunAck)
		require.NoError(t, err)
		require.Equal(t, value, got)
	})
}

func FuzzDtlsInStunAttribute(f *testing.F) {
	f.Add([]byte{})
	f.Add(spedWireVectorDTLS)

	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > 0xffff-stunAttributeHeaderLen {
			return
		}
		msg := new(stun.Message)
		require.NoError(t, DtlsInStunAttribute(value).AddTo(msg))
		msg.WriteHeader()

		decoded := &stun.Message{Raw: append([]byte{}, msg.Raw...)}
		require.NoError(t, decoded.Decode())

		var data DtlsInStunAttribute
		require.NoError(t, data.GetFrom(decoded))
		require.Equal(t, value, []byte(data))
	})
}

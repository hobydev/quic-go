package wire

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// Header is the header of a QUIC packet.
// It contains fields that are only needed for the gQUIC Public Header and the IETF draft Header.
type Header struct {
	IsPublicHeader bool

	Raw []byte

	Version protocol.VersionNumber

	DestConnectionID     protocol.ConnectionID
	SrcConnectionID      protocol.ConnectionID
	OrigDestConnectionID protocol.ConnectionID // only needed in the Retry packet

	PacketNumberLen protocol.PacketNumberLen
	PacketNumber    protocol.PacketNumber

	IsVersionNegotiation bool
	SupportedVersions    []protocol.VersionNumber // Version Number sent in a Version Negotiation Packet by the server

	// only needed for the gQUIC Public Header
	VersionFlag          bool
	ResetFlag            bool
	DiversificationNonce []byte

	// only needed for the IETF Header
	Type         protocol.PacketType
	IsLongHeader bool
	KeyPhase     int
	PayloadLen   protocol.ByteCount
	Token        []byte
}

var errInvalidPacketNumberLen = errors.New("invalid packet number length")

// Write writes the Header.
func (h *Header) Write(b *bytes.Buffer, pers protocol.Perspective, ver protocol.VersionNumber) error {
	if h.IsLongHeader {
		return h.writeLongHeader(b, ver)
	}
	return h.writeShortHeader(b, ver)
}

// TODO: add support for the key phase
func (h *Header) writeLongHeader(b *bytes.Buffer, v protocol.VersionNumber) error {
	b.WriteByte(byte((1 << 7) | (1 << 6) | byte(h.Type<<4) | byte(h.PacketNumberLen-1)))

	utils.BigEndian.WriteUint32(b, uint32(h.Version))
	connIDLen, err := encodeConnIDLen(h.DestConnectionID, h.SrcConnectionID)
	if err != nil {
		return err
	}
	b.WriteByte(connIDLen)
	b.Write(h.DestConnectionID.Bytes())
	b.Write(h.SrcConnectionID.Bytes())

	if h.Type == protocol.PacketTypeInitial && v.UsesTokenInHeader() {
		utils.WriteVarInt(b, uint64(len(h.Token)))
		b.Write(h.Token)
	}

	if h.Type == protocol.PacketTypeRetry {
		odcil, err := encodeSingleConnIDLen(h.OrigDestConnectionID)
		if err != nil {
			return err
		}
		// randomize the first 4 bits
		odcilByte := make([]byte, 1)
		_, _ = rand.Read(odcilByte) // it's safe to ignore the error here
		odcilByte[0] = (odcilByte[0] & 0xf0) | odcil
		b.Write(odcilByte)
		b.Write(h.OrigDestConnectionID.Bytes())
		b.Write(h.Token)
		return nil
	}

	if v.UsesLengthInHeader() {
		utils.WriteVarInt(b, uint64(h.PayloadLen))
	}
	if v.UsesVarintPacketNumbers() {
		return utils.WriteVarIntPacketNumber(b, h.PacketNumber, h.PacketNumberLen)
	}
	utils.BigEndian.WriteUintN(b, uint64(h.PacketNumber), uint8(h.PacketNumberLen))
	if h.Type == protocol.PacketType0RTT {
		if len(h.DiversificationNonce) != 32 {
			return errors.New("invalid diversification nonce length")
		}
		b.Write(h.DiversificationNonce)
	}
	return nil
}

func (h *Header) writeShortHeader(b *bytes.Buffer, v protocol.VersionNumber) error {
	b.WriteByte(byte((1 << 7) | (h.PacketNumberLen - 1)))

	b.Write(h.DestConnectionID.Bytes())
	if !v.UsesVarintPacketNumbers() {
		utils.BigEndian.WriteUintN(b, uint64(h.PacketNumber), uint8(h.PacketNumberLen))
	}
	return utils.WriteVarIntPacketNumber(b, h.PacketNumber, h.PacketNumberLen)
}

// GetLength determines the length of the Header.
func (h *Header) GetLength(v protocol.VersionNumber) (protocol.ByteCount, error) {
	if !v.UsesIETFHeaderFormat() {
		return h.getPublicHeaderLength()
	}
	return h.getHeaderLength(v)
}

func (h *Header) getHeaderLength(v protocol.VersionNumber) (protocol.ByteCount, error) {
	if h.IsLongHeader {
		length := 1 /* type byte */ + 4 /* version */ + 1 /* conn id len byte */ + protocol.ByteCount(h.DestConnectionID.Len()+h.SrcConnectionID.Len()) + protocol.ByteCount(h.PacketNumberLen)
		if v.UsesLengthInHeader() {
			length += utils.VarIntLen(uint64(h.PayloadLen))
		}
		if h.Type == protocol.PacketTypeInitial && v.UsesTokenInHeader() {
			length += utils.VarIntLen(uint64(len(h.Token))) + protocol.ByteCount(len(h.Token))
		}
		// *** Still do?
		if h.Type == protocol.PacketType0RTT {
			length += protocol.ByteCount(len(h.DiversificationNonce))
		}
		return length, nil
	}

	length := protocol.ByteCount(1 /* type byte */ + h.DestConnectionID.Len())
	if h.PacketNumberLen != protocol.PacketNumberLen1 && h.PacketNumberLen != protocol.PacketNumberLen2 && h.PacketNumberLen != protocol.PacketNumberLen4 {
		return 0, fmt.Errorf("invalid packet number length: %d", h.PacketNumberLen)
	}
	length += protocol.ByteCount(h.PacketNumberLen)
	return length, nil
}

// getPublicHeaderLength gets the length of the publicHeader in bytes.
// It can only be called for regular packets.
func (h *Header) getPublicHeaderLength() (protocol.ByteCount, error) {
	length := protocol.ByteCount(1) // 1 byte for public flags
	if h.PacketNumberLen == protocol.PacketNumberLen6 {
		return 0, errInvalidPacketNumberLen
	}
	if h.PacketNumberLen != protocol.PacketNumberLen1 && h.PacketNumberLen != protocol.PacketNumberLen2 && h.PacketNumberLen != protocol.PacketNumberLen4 {
		return 0, errPacketNumberLenNotSet
	}
	length += protocol.ByteCount(h.PacketNumberLen)
	length += protocol.ByteCount(h.DestConnectionID.Len())
	// Version Number in packets sent by the client
	if h.VersionFlag {
		length += 4
	}
	length += protocol.ByteCount(len(h.DiversificationNonce))
	return length, nil
}

// Log logs the Header
func (h *Header) Log(logger utils.Logger) {
	if h.IsPublicHeader {
		h.logPublicHeader(logger)
	} else {
		h.logHeader(logger)
	}
}

func (h *Header) logHeader(logger utils.Logger) {
	if h.IsLongHeader {
		if h.Version == 0 {
			logger.Debugf("\tVersionNegotiationPacket{DestConnectionID: %s, SrcConnectionID: %s, SupportedVersions: %s}", h.DestConnectionID, h.SrcConnectionID, h.SupportedVersions)
		} else {
			var token string
			if h.Type == protocol.PacketTypeInitial || h.Type == protocol.PacketTypeRetry {
				if len(h.Token) == 0 {
					token = "Token: (empty), "
				} else {
					token = fmt.Sprintf("Token: %#x, ", h.Token)
				}
			}
			if h.Type == protocol.PacketTypeRetry {
				logger.Debugf("\tLong Header{Type: %s, DestConnectionID: %s, SrcConnectionID: %s, %sOrigDestConnectionID: %s, Version: %s}", h.Type, h.DestConnectionID, h.SrcConnectionID, token, h.OrigDestConnectionID, h.Version)
				return
			}
			// *** Still do?
			{
				var divNonce string
				if h.Type == protocol.PacketType0RTT {
					divNonce = fmt.Sprintf("Diversification Nonce: %#x, ", h.DiversificationNonce)
				}
				logger.Debugf("\tLong Header{Type: %s, DestConnectionID: %s, SrcConnectionID: %s, PacketNumber: %#x, PacketNumberLen: %d, %sVersion: %s}", h.Type, h.DestConnectionID, h.SrcConnectionID, h.PacketNumber, h.PacketNumberLen, divNonce, h.Version)
				return
			}
			logger.Debugf("\tLong Header{Type: %s, DestConnectionID: %s, SrcConnectionID: %s, %sPacketNumber: %#x, PacketNumberLen: %d, PayloadLen: %d, Version: %s}", h.Type, h.DestConnectionID, h.SrcConnectionID, token, h.PacketNumber, h.PacketNumberLen, h.PayloadLen, h.Version)
		}
	} else {
		logger.Debugf("\tShort Header{DestConnectionID: %s, PacketNumber: %#x, PacketNumberLen: %d, KeyPhase: %d}", h.DestConnectionID, h.PacketNumber, h.PacketNumberLen, h.KeyPhase)
	}
}

func (h *Header) logPublicHeader(logger utils.Logger) {
	ver := "(unset)"
	if h.Version != 0 {
		ver = h.Version.String()
	}
	logger.Debugf("\tPublic Header{ConnectionID: %s, PacketNumber: %#x, PacketNumberLen: %d, Version: %s, DiversificationNonce: %#v}", h.DestConnectionID, h.PacketNumber, h.PacketNumberLen, ver, h.DiversificationNonce)
}

func encodeConnIDLen(dest, src protocol.ConnectionID) (byte, error) {
	dcil, err := encodeSingleConnIDLen(dest)
	if err != nil {
		return 0, err
	}
	scil, err := encodeSingleConnIDLen(src)
	if err != nil {
		return 0, err
	}
	return scil | dcil<<4, nil
}

func encodeSingleConnIDLen(id protocol.ConnectionID) (byte, error) {
	len := id.Len()
	if len == 0 {
		return 0, nil
	}
	if len < 4 || len > 18 {
		return 0, fmt.Errorf("invalid connection ID length: %d bytes", len)
	}
	return byte(len - 3), nil
}

func decodeConnIDLen(enc byte) (int /*dest conn id len*/, int /*src conn id len*/) {
	return decodeSingleConnIDLen(enc >> 4), decodeSingleConnIDLen(enc & 0xf)
}

func decodeSingleConnIDLen(enc uint8) int {
	if enc == 0 {
		return 0
	}
	return int(enc) + 3
}

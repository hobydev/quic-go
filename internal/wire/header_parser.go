package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// The InvariantHeader is the version independent part of the header
type InvariantHeader struct {
	IsLongHeader     bool
	Version          protocol.VersionNumber
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID

	typeByte byte
}

// ParseInvariantHeader parses the version independent part of the header
func ParseInvariantHeader(b *bytes.Reader, shortHeaderConnIDLen int) (*InvariantHeader, error) {
	typeByte, err := b.ReadByte()
	fmt.Printf("QUIC: typeByte = %v\n", typeByte)
	if err != nil {
		return nil, err
	}

	h := &InvariantHeader{typeByte: typeByte}
	h.IsLongHeader = typeByte&0x80 > 0
	fmt.Printf("QUIC: IsLongHeader = %v\n", h.IsLongHeader)

	// If this is not a Long Header, it could either be a Public Header or a Short Header.
	if !h.IsLongHeader {
		// In the Public Header 0x8 is the Connection ID Flag.
		// In the IETF Short Header:
		// * 0x8 it is the gQUIC Demultiplexing bit, and always 0.
		// * 0x20 and 0x10 are always 1.
		var connIDLen int
		if typeByte&0x8 > 0 { // Public Header containing a connection ID
			connIDLen = 8
		}
		if typeByte&0x38 == 0x30 { // Short Header
			connIDLen = shortHeaderConnIDLen
		}
		if connIDLen > 0 {
			h.DestConnectionID, err = protocol.ReadConnectionID(b, connIDLen)
			if err != nil {
				return nil, err
			}
		}
		return h, nil
	}
	// Long Header
	v, err := utils.BigEndian.ReadUint32(b)
	if err != nil {
		return nil, err
	}
	var printable []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(printable, v)
	fmt.Printf("QUIC: version = %s\n", string(printable))

	h.Version = protocol.VersionNumber(v)
	connIDLenByte, err := b.ReadByte()
	fmt.Printf("QUIC: connIDLenByte = %d\n", connIDLenByte)
	if err != nil {
		return nil, err
	}
	dcil, scil := decodeConnIDLen(connIDLenByte)
	h.DestConnectionID, err = protocol.ReadConnectionID(b, dcil)
	fmt.Printf("QUIC: DestConnectionID = %#x\n", h.DestConnectionID)
	if err != nil {
		return nil, err
	}
	h.SrcConnectionID, err = protocol.ReadConnectionID(b, scil)
	fmt.Printf("QUIC: SrcConnectionID = %#x\n", h.SrcConnectionID)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// Parse parses the version dependent part of the header
func (iv *InvariantHeader) Parse(b *bytes.Reader, sentBy protocol.Perspective, ver protocol.VersionNumber) (*Header, error) {
	if iv.IsLongHeader {
		if iv.Version == 0 { // Version Negotiation Packet
			return iv.parseVersionNegotiationPacket(b)
		}
		return iv.parseLongHeader(b, sentBy, ver)
	}
	return iv.parseShortHeader(b, ver)
}

func (iv *InvariantHeader) toHeader() *Header {
	return &Header{
		IsLongHeader:     iv.IsLongHeader,
		DestConnectionID: iv.DestConnectionID,
		SrcConnectionID:  iv.SrcConnectionID,
		Version:          iv.Version,
	}
}

func (iv *InvariantHeader) parseVersionNegotiationPacket(b *bytes.Reader) (*Header, error) {
	h := iv.toHeader()
	h.VersionFlag = true
	if b.Len() == 0 {
		return nil, qerr.Error(qerr.InvalidVersionNegotiationPacket, "empty version list")
	}
	h.IsVersionNegotiation = true
	h.SupportedVersions = make([]protocol.VersionNumber, b.Len()/4)
	for i := 0; b.Len() > 0; i++ {
		v, err := utils.BigEndian.ReadUint32(b)
		if err != nil {
			return nil, qerr.InvalidVersionNegotiationPacket
		}
		h.SupportedVersions[i] = protocol.VersionNumber(v)
	}
	return h, nil
}

func (iv *InvariantHeader) parseLongHeader(b *bytes.Reader, sentBy protocol.Perspective, v protocol.VersionNumber) (*Header, error) {
	h := iv.toHeader()
	h.Type = protocol.PacketType((iv.typeByte & 0x30) >> 4)
	log.Printf("QUIC: h.Type = %#x from iv.typeByte", h.Type)

	if h.Type != protocol.PacketTypeInitial && h.Type != protocol.PacketTypeRetry && h.Type != protocol.PacketType0RTT && h.Type != protocol.PacketTypeHandshake {
		return nil, qerr.Error(qerr.InvalidPacketHeader, fmt.Sprintf("Received packet with invalid packet type: %d", h.Type))
	}

	if h.Type == protocol.PacketTypeRetry {
		odcilByte, err := b.ReadByte()
		if err != nil {
			return nil, err
		}
		odcil := decodeSingleConnIDLen(odcilByte & 0xf)
		h.OrigDestConnectionID, err = protocol.ReadConnectionID(b, odcil)
		if err != nil {
			return nil, err
		}
		h.Token = make([]byte, b.Len())
		if _, err := io.ReadFull(b, h.Token); err != nil {
			return nil, err
		}
		return h, nil
	}

	if h.Type == protocol.PacketTypeInitial && v.UsesTokenInHeader() {
		tokenLen, err := utils.ReadVarInt(b)
		if err != nil {
			return nil, err
		}
		if tokenLen > uint64(b.Len()) {
			return nil, io.EOF
		}
		h.Token = make([]byte, tokenLen)
		if _, err := io.ReadFull(b, h.Token); err != nil {
			return nil, err
		}
	}

	if v.UsesLengthInHeader() {
		pl, err := utils.ReadVarInt(b)
		if err != nil {
			return nil, err
		}
		h.PayloadLen = protocol.ByteCount(pl)
	}
	if v.UsesVarintPacketNumbers() {
		pn, pnLen, err := utils.ReadVarIntPacketNumber(b)
		if err != nil {
			return nil, err
		}
		h.PacketNumber = pn
		h.PacketNumberLen = pnLen
	} else {
		h.PacketNumberLen = protocol.PacketNumberLen((iv.typeByte & 0x03) + 1)
		p, err := utils.BigEndian.ReadUintN(b, uint8(h.PacketNumberLen))
		if err != nil {
			return nil, err
		}
		h.PacketNumber = protocol.PacketNumber(p)
	}
	if h.Type == protocol.PacketType0RTT && sentBy == protocol.PerspectiveServer {
		h.DiversificationNonce = make([]byte, 32)
		if _, err := io.ReadFull(b, h.DiversificationNonce); err != nil {
			if err == io.ErrUnexpectedEOF {
				return nil, io.EOF
			}
			return nil, err
		}
	}

	return h, nil
}

func (iv *InvariantHeader) parseShortHeader(b *bytes.Reader, v protocol.VersionNumber) (*Header, error) {
	h := iv.toHeader()
	h.KeyPhase = int(iv.typeByte&0x40) >> 6

	if v.UsesVarintPacketNumbers() {
		pn, pnLen, err := utils.ReadVarIntPacketNumber(b)
		if err != nil {
			return nil, err
		}
		h.PacketNumber = pn
		h.PacketNumberLen = pnLen
	} else {
		h.PacketNumberLen = protocol.PacketNumberLen((iv.typeByte & 0x03) + 1)
		p, err := utils.BigEndian.ReadUintN(b, uint8(h.PacketNumberLen))
		if err != nil {
			return nil, err
		}
		h.PacketNumber = protocol.PacketNumber(p)
	}
	return h, nil
}

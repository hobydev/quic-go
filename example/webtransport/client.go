package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func main() {
	logger := utils.DefaultLogger.WithPrefix("QUIC: ")
	logger.SetLogLevel(utils.LogLevelDebug)
	quicConfig := &quic.Config{
		MaxIncomingStreams:    1000,
		MaxIncomingUniStreams: 1000,
		AcceptCookie:          func(net.Addr, *handshake.Cookie) bool { return true },
		KeepAlive:             true,
		PreSharedKey:          []byte("default-psk"),
		Logger:                logger,
		Versions:              []protocol.VersionNumber{protocol.Version46},
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	session, err := quic.DialAddr("localhost:3737", tlsConfig, quicConfig)
	if err != nil {
		panic(err)
	}

	stream, err := session.OpenStreamSync()
	if err != nil {
		panic(err)
	}

	message := "test message"
	fmt.Printf("Client: Sending '%s'\n", message)
	_, err = stream.Write([]byte(message))
	if err != nil {
		panic(err)
	}

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Client: Got '%s'\n", buf)
}

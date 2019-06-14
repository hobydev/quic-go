package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/handshake"
)

var (
	httpPort = 3030
	icePort  = 3737
	fileRoot = "./example/webtransport/"
)

type clientRequest struct {
	quicPsk     []byte
	iceUsername string
	response    chan clientResponse
}

type clientResponse struct {
	iceHost     string
	icePort     int
	icePassword string
}

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	requests := make(chan clientRequest)
	go runSignalingServer(requests)

	conns := make(chan net.PacketConn)
	go runIceServer(requests, conns)

	tlsCert := generateTlsCert()
	for conn := range conns {
		go runQuicServer(conn, tlsCert)
	}
}

func runSignalingServer(requests chan<- clientRequest) {
	// For client.html and client.js
	http.Handle("/", http.FileServer(http.Dir(fileRoot)))
	http.HandleFunc("/web-transport", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "quic-psk,ice-username-fragment")
		w.Header().Set("Access-Control-Expose-Headers", "ice-host,ice-port,ice-password")
		// log.Printf("%v", r.Header)
		quicPskHex := r.Header.Get("quic-psk")
		quicPsk, _ := hex.DecodeString(quicPskHex)
		iceUsernameFragment := r.Header.Get("ice-username-fragment")
		if len(quicPsk) == 0 || len(iceUsernameFragment) == 0 {
			if len(r.Header.Get("Access-Control-Request-Headers")) > 0 {
				// It's a pre-flight request.
				// log.Printf("Returning from pre-flight request.\n")
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
			return
		}

		iceUsername := strings.Join([]string{iceUsernameFragment, iceUsernameFragment}, ":")
		responseChan := make(chan clientResponse, 1)
		requests <- clientRequest{quicPsk: quicPsk, iceUsername: iceUsername, response: responseChan}
		response := <-responseChan
		w.Header().Set("ice-host", response.iceHost)
		w.Header().Set("ice-port", strconv.Itoa(response.icePort))
		w.Header().Set("ice-password", response.icePassword)
		w.WriteHeader(http.StatusOK)
	})

	httpAddress := net.JoinHostPort("", strconv.Itoa(httpPort))
	log.Fatal(http.ListenAndServe(httpAddress, nil))
}

type iceConn struct {
	udp             net.PacketConn
	remoteAddr      net.Addr
	username        string
	password        string
	receivedPackets chan []byte
}

func (ice *iceConn) Close() error {
	close(ice.receivedPackets)
	return nil
}

func (ice *iceConn) LocalAddr() net.Addr {
	return ice.udp.LocalAddr()
}

func (ice *iceConn) RemoteAddr() net.Addr {
	return iceAddr(ice.username)
}

type iceAddr string

func (ia iceAddr) String() string {
	return string(ia)
}

func (ia iceAddr) Network() string {
	return "ice"
}

func (ice *iceConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// TODO: Handle close
	packet := <-ice.receivedPackets
	copy(b, packet)
	return len(packet), ice.RemoteAddr(), nil
}

func (ice *iceConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	log.Printf("Send packet of size %d to %s", len(p), addr)
	if addr != ice.RemoteAddr() {
		return 0, errors.New("You can't change the remote address when sending with ICE")
	}
	return ice.udp.WriteTo(p, addr)
}

func (ice iceConn) SetDeadline(t time.Time) error {
	// TODO
	return errors.New("SetDeadline not supported.")
}

func (ice iceConn) SetReadDeadline(t time.Time) error {
	// TODO
	return errors.New("SetReadDeadline not supported.")
}

func (ice iceConn) SetWriteDeadline(t time.Time) error {
	// TODO
	return errors.New("SetWriteDeadline not supported.")
}

type udpPacket struct {
	sender net.Addr
	data   []byte
}

func runIceServer(requests <-chan clientRequest, conns chan<- net.PacketConn) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: nil, Port: icePort})
	if err != nil {
		log.Fatalf("Failed to open UDP port %d: '%s'\n", icePort, err)
	}

	// Put packets into a channel so we can select on packets and client requests
	udpPackets := make(chan udpPacket)
	go func(udpPackets chan<- udpPacket) {
		buffer := make([]byte, 1500)
		for {
			size, addr, err := udp.ReadFromUDP(buffer[:])
			if err != nil {
				close(udpPackets)
				log.Fatalf("Failed to read UDP packet: '%s'\n", err)
				break
			}
			data := make([]byte, size)
			copy(data, buffer)
			udpPackets <- udpPacket{data: data, sender: addr}
		}
	}(udpPackets)

	iceConnByUsername := make(map[string]*iceConn)
	iceConnByRemoteAddr := make(map[net.Addr]*iceConn)
	for {
		select {
		case request := <-requests:
			log.Printf("Got client request with ICE username %s\n", request.iceUsername)
			// TODO: make random
			// TODO: Fix this; not stuck with ipv6
			// host, _, _ := net.SplitHostPort(udp.LocalAddr().String())
			host := "127.0.0.1"
			icePassword := "password"
			request.response <- clientResponse{
				iceHost:     host,
				icePort:     icePort,
				icePassword: icePassword,
			}
			iceConn := &iceConn{udp: udp, username: request.iceUsername, password: icePassword, receivedPackets: make(chan []byte)}
			iceConnByUsername[iceConn.username] = iceConn
			conns <- iceConn
		case udpPacket := <-udpPackets:
			log.Printf("Read packet of size %d from %s.\n", len(udpPacket.data), udpPacket.sender)
			stun := quic.VerifyStunPacket(udpPacket.data)
			isIceCheck := (stun != nil && stun.Type() == quic.StunBindingRequest && stun.ValidateFingerprint())
			if isIceCheck {
				iceConn, ok := iceConnByUsername[stun.Username()]
				if !ok {
					log.Printf("ICE check from unknown username %s", stun.Username())
				}
				if !stun.ValidateMessageIntegrity([]byte(iceConn.password)) {
					log.Printf("ICE check has bad message integrity.\n")
					continue
				}
				response := quic.NewStunPacket(quic.StunBindingResponse, stun.TransactionId()).AppendMessageIntegrity([]byte(iceConn.password)).AppendFingerprint()
				_, err = udp.WriteTo(response, udpPacket.sender)
				if err != nil {
					log.Printf("Failed to write ICE check response.\n")
				}
				// log.Printf("New username: %s\n", stun.Username())
				iceConn.remoteAddr = udpPacket.sender
				iceConnByRemoteAddr[udpPacket.sender] = iceConn
			} else {
				iceConn, ok := iceConnByRemoteAddr[udpPacket.sender]
				if !ok {
					log.Printf("Received non-ICE packet from unkonwn address: %s\n", udpPacket.sender)
				}
				iceConn.receivedPackets <- udpPacket.data
			}
		}
	}
}

func runQuicServer(conn net.PacketConn, tlsCert tls.Certificate) {
	quicConfig := &quic.Config{
		MaxIncomingStreams:    1000,
		MaxIncomingUniStreams: 1000,
		AcceptCookie:          func(net.Addr, *handshake.Cookie) bool { return true },
		KeepAlive:             true,
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		Certificates:       []tls.Certificate{tlsCert},
	}
	listener, err := quic.Listen(conn, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("Could not quic.Listen().")
	}
	session, err := listener.Accept()
	log.Printf("Got a session!\n")
	if err != nil {
		log.Fatalf("Could not listener.Accept().")
	}
	stream, err := session.AcceptStream()
	if err != nil {
		log.Fatalf("Could not session.AcceptStream().")
	}
	log.Printf("Got a stream! StreamID = %s", stream.StreamID())
}

func generateTlsCert() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("Could not generate RSA key.")
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("Could not create certificate.")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Could not create TLS cert.")
	}
	return tlsCert
}

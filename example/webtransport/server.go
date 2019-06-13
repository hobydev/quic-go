package main

import (
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strconv"

	quic "github.com/lucas-clemente/quic-go"
)

var (
	httpPort = 3030
	icePort  = 3737
	fileRoot = "./example/webtransport/"
)

type clientRequest struct {
	quicPsk             []byte
	iceUsernameFragment string
	response            chan clientResponse
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
	runIceQuicServer(requests)
}

func runSignalingServer(requests chan<- clientRequest) {
	// For client.html and client.js
	http.Handle("/", http.FileServer(http.Dir(fileRoot)))
	http.HandleFunc("/web-transport", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "quic-psk,ice-username-fragment")
		w.Header().Set("Access-Control-Expose-Headers", "ice-host,ice-port,ice-password")
		log.Printf("%v", r.Header)
		quicPskHex := r.Header.Get("quic-psk")
		quicPsk, _ := hex.DecodeString(quicPskHex)
		iceUsernameFragment := r.Header.Get("ice-username-fragment")
		if len(quicPsk) == 0 || len(iceUsernameFragment) == 0 {
			if len(r.Header.Get("Access-Control-Request-Headers")) > 0 {
				// It's a pre-flight request.
				log.Printf("Returning from pre-flight request.\n")
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
			return
		}

		responseChan := make(chan clientResponse, 1)
		requests <- clientRequest{quicPsk: quicPsk, iceUsernameFragment: iceUsernameFragment, response: responseChan}
		response := <-responseChan
		w.Header().Set("ice-host", response.iceHost)
		w.Header().Set("ice-port", strconv.Itoa(response.icePort))
		w.Header().Set("ice-password", response.icePassword)
		w.WriteHeader(http.StatusOK)
	})

	log.Fatal(http.ListenAndServe(net.JoinHostPort("", strconv.Itoa(httpPort)), nil))
}

func runIceQuicServer(requests <-chan clientRequest) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: nil, Port: icePort})
	if err != nil {
		log.Fatalf("Failed to open UDP port %d: '%s'\n", icePort, err)
	}

	// host, _, _ := net.SplitHostPort(udp.LocalAddr().String())
	// *** TODO: Fix this; not stuck with ipv6
	host := "127.0.0.1"
	icePassword := "password"
	// *** TODO: Have a random password
	// *** TODO: handle more than one at a time
	for request := range requests {
		log.Printf("Got client request with ICE ufrag %s\n", request.iceUsernameFragment)
		request.response <- clientResponse{
			iceHost:     host,
			icePort:     icePort,
			icePassword: "password",
		}
		log.Printf("Listening for ICE and QUIC on %s for password %s.\n", udp.LocalAddr(), icePassword)

		buffer := make([]byte, 1500)
		for {
			size, addr, err := udp.ReadFromUDP(buffer[:])
			log.Printf("Read packet of size %d from %s.\n", size, addr)
			p := buffer[:size]
			if err != nil {
				log.Fatalf("Failed to read UDP packet: '%s'\n", err)
			}

			stun := quic.VerifyStunPacket(p)
			isIceCheck := (stun != nil && stun.Type() == quic.StunBindingRequest && stun.ValidateFingerprint())
			if isIceCheck {
				if !stun.ValidateMessageIntegrity([]byte(icePassword)) {
					log.Printf("ICE check has bad message integrity.\n")
					continue
				}
				response := quic.NewStunPacket(quic.StunBindingResponse, stun.TransactionId()).AppendMessageIntegrity([]byte(icePassword)).AppendFingerprint()
				_, err = udp.WriteTo(response, addr)
				if err != nil {
					log.Printf("Failed to write ICE check response.\n")
				}
			} else {
				log.Printf("Read unknown packet of size %d from %s.\n", size, addr)
			}
		}
	}
}

// QUIC server
//  quicConfig := {
//    MaxIncomingStreams: 1000,
//    MaxIncomingUniStreams: 1000,
//    AcceptCookie: func(...) bool { return true; } // ???
//    KeepAlive: true,  // ???
//  }
//  tlsConfig := {
//    InsecureSkipVerify: true,  // ???
//    ClientAuth: tls.RequireAnyClientCert,  // ???
//    Certificates: []tls.Certificate{{
//     generateTlsCert()
//    }}
//  }
//  listener, err := quic.Listen(iceConn, tlsConfig, quicConfig)
//  sess, err := l.Accept()
//  stream, err := sess.AcceptStream()
//  ... Read, Write, StreamID, Close

//	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
//	sess, err := listener.Accept()
//	stream, err := sess.AcceptStream()
//	_, err = io.Copy(loggingWriter{stream}, stream)

// QUIC client
//  session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, nil)
//	stream, err := session.OpenStreamSync()
//	_, err = stream.Write([]byte(message))

//	buf := make([]byte, len(message))
//	_, err = io.ReadFull(stream, buf)

/*
func generateTlsCert() *tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return tlsCert
}
*/

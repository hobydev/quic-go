// TODO:
//

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	quic "github.com/lucas-clemente/quic-go"
)

var (
	httpPort    = ":3030"
	iceAddress  = "127.0.0.1"
	icePort     = 3737
	icePassword = "password"

	// If any of these are set, an HTTP server will be run
	iceAddressUrl  = "/ice-address"
	icePortUrl     = "/ice-port"
	icePasswordUrl = "/ice-password"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	if len(iceAddressUrl) > 0 || len(iceAddressUrl) > 0 || len(icePasswordUrl) > 0 {
		go runHttpServer()
	}
	runIceQuicServer()
}

func runHttpServer() {
	http.HandleFunc(iceAddressUrl, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, iceAddress)
	})
	http.HandleFunc(icePortUrl, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, icePort)
	})
	http.HandleFunc(icePasswordUrl, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, icePassword)
	})

	http.Handle("/", http.FileServer(http.Dir(".")))

	log.Fatal(http.ListenAndServe(httpPort, nil))
}

func runIceQuicServer() {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: nil, Port: icePort})
	if err != nil {
		log.Fatalf("Failed to open UDP port %d: '%s'\n", icePort, err)
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

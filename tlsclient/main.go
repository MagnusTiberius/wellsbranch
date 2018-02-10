package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {

	cert, err := tls.LoadX509KeyPair("certs/client/cert.pem", "certs/client/key.pem")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "127.0.0.1:8000", &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println(v.Subject)
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

	message := "Hello\n"
	n, err := io.WriteString(conn, message)
	if err != nil {
		log.Fatalf("client: write: %s", err)
	}
	log.Printf("client: wrote %q (%d bytes)", message, n)

	reply := make([]byte, 256)
	n, err = conn.Read(reply)
	log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)

	reader := bufio.NewReader(os.Stdin)
	for {
		message, _ := reader.ReadString('\n')
		n, err := io.WriteString(conn, message)
		if err != nil {
			log.Fatalf("client: write: %s", err)
			break
		}
		log.Printf("client: wrote %q (%d bytes)", message, n)
	}

	log.Print("client: exiting")
}
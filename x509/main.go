package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func genkey() {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)

	publicKey := key.PublicKey

	saveGobKey("private.key", key)
	savePEMKey("private.pem", key)

	saveGobKey("public.key", publicKey)
	savePublicPEMKey("public.pem", publicKey)
}

func loadstore() {

	// Create the keys
	priv, pub := GenerateRsaKeyPair()

	// Export the keys to pem string
	priv_pem := ExportRsaPrivateKeyAsPemStr(priv)
	pub_pem, _ := ExportRsaPublicKeyAsPemStr(pub)

	// Import the keys from pem string
	priv_parsed, _ := ParseRsaPrivateKeyFromPemStr(priv_pem)
	pub_parsed, _ := ParseRsaPublicKeyFromPemStr(pub_pem)

	// Export the newly imported keys
	priv_parsed_pem := ExportRsaPrivateKeyAsPemStr(priv_parsed)
	pub_parsed_pem, _ := ExportRsaPublicKeyAsPemStr(pub_parsed)

	fmt.Println(priv_parsed_pem)
	fmt.Println(pub_parsed_pem)

	// Check that the exported/imported keys match the original keys
	if priv_pem != priv_parsed_pem || pub_pem != pub_parsed_pem {
		fmt.Println("Failure: Export and Import did not result in same Keys")
	} else {
		fmt.Println("Success")
	}
}

func main() {
	genkey()
	loadstore()
}

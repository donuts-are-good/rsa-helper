package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func main() {
  
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA key:", err)
		return
	}

	// Encode private key as PEM data
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	// Encode public key as PEM data
	publicKey := &privateKey.PublicKey
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(publicKey),
		},
	)

	// Sign message "hello world"
	message := []byte("hello world")
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}

	// Encrypt message
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, message, nil)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	// Decrypt message
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	// Verify signature
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Println("Error verifying signature:", err)
		return
	}

	// Print results
	fmt.Printf("\nPrivate Key: %s\n", privateKeyPEM)
	fmt.Printf("\nPublic Key: %s\n", publicKeyPEM)
	fmt.Println("Signature:", signature)
	fmt.Println("Ciphertext:", ciphertext)
	fmt.Println("Plaintext:", string(plaintext))
	fmt.Println("Signature verification successful")
}

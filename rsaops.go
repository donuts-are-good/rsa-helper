package rsaops

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Generate creates a new RSA key pair with a key length of 2048 bits.
// It returns a private key and its corresponding public key.
// In case of an error generating the key pair, it returns empty private and public keys.
func Generate() (rsa.PrivateKey, rsa.PublicKey) {

	// Generate a new RSA key pair with a key length of 2048 bits
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {

		// If there is an error generating the key, print the error message and return empty private and public keys
		fmt.Println("Error generating RSA key:", err)
		return rsa.PrivateKey{}, rsa.PublicKey{}
	}

	// Return the private key and its corresponding public key
	return *privateKey, privateKey.PublicKey

}

// PrivateKeyAsPEM takes a pointer to an RSA private key and returns its PEM encoding as a byte slice.
func PrivateKeyAsPEM(pk *rsa.PrivateKey) []byte {
	// Encode the private key as PEM data
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pk),
		},
	)

	// Return the PEM-encoded private key
	return privateKeyPEM

}

// PublicKeyAsPEM takes a pointer to an RSA private key and returns its corresponding public key's PEM encoding as a byte slice.
func PublicKeyAsPEM(pk *rsa.PrivateKey) []byte {

	// Get the public key corresponding to the private key
	publicKey := &pk.PublicKey

	// Encode the public key as PEM data
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(publicKey),
		},
	)

	// Return the PEM-encoded public key
	return publicKeyPEM

}

// Sign takes a message as a byte slice and an RSA private key, and returns a digital signature of the message as a byte slice.
func Sign(msg []byte, pk *rsa.PrivateKey) []byte {

	// Hash the message using SHA-256
	hashed := sha256.Sum256(msg)

	// Sign the hashed message using the private key and SHA-256
	signature, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, hashed[:])
	if err != nil {

		// If there is an error signing the message, print the error message and return an empty byte slice
		fmt.Println("Error signing message:", err)
		return []byte{}
	}

	// Return the signature
	return signature

}

func Verify(msg []byte, signature []byte, pk *rsa.PrivateKey) error {

	hashed := sha256.Sum256(msg)

	err := rsa.VerifyPKCS1v15(&pk.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Println("Error verifying signature:", err)

	}

	return err
}

// Encrypt takes a message as a byte slice and an RSA public key, and returns the encrypted message as a byte slice.
func Encrypt(msg []byte, pk *rsa.PrivateKey) []byte {

	// Encrypt the message using RSA OAEP with SHA-256
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pk.PublicKey, msg, nil)
	if err != nil {

		// If there is an error encrypting the message, print the error message and return an empty byte slice
		fmt.Println("Error encrypting message:", err)
		return []byte{}
	}

	// Return the encrypted message
	return ciphertext

}

// Decrypt takes a message as a byte slice and an RSA private key, and returns the decrypted message as a byte slice.
func Decrypt(msg []byte, pk *rsa.PrivateKey) []byte {

	// Decrypt the message using RSA OAEP with SHA-256
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, pk, msg, nil)
	if err != nil {

		// If there is an error decrypting the message, print the error message and return an empty byte slice
		fmt.Println("Error decrypting message:", err)
		return []byte{}
	}

	// Return the decrypted message
	return plaintext

}

package rsaops

import (
	"bytes"
	"encoding/pem"
	"testing"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name      string
		keyLength int
		sigVerify bool
	}{
		{"Test key length 2048", 2048, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Logf("Generating keys: %s", test.name)
			privateKey, publicKey := Generate()
			t.Logf("Running private key length test: %s", test.name)
			if privateKey.N.BitLen() != test.keyLength {
				t.Errorf("Expected key length to be %d, but got %d", test.keyLength, privateKey.N.BitLen())
			}
			t.Logf("Running public key length test: %s", test.name)
			if publicKey.N.BitLen() != test.keyLength {
				t.Errorf("Expected key length to be %d, but got %d", test.keyLength, publicKey.N.BitLen())
			}
			t.Logf("Running message sig-verify test: %v", test.sigVerify)
			message := []byte("test message")
			signature := Sign(message, &privateKey)
			if err := Verify(message, signature, &privateKey); err != nil {
				if test.sigVerify {
					t.Errorf("Signature verification failed: %s", err)
				}
			} else {
				if !test.sigVerify {
					t.Errorf("Signature verification should have failed")
				}
			}
		})
	}
}

func TestPrivateKeyAsPEM(t *testing.T) {
	privateKey, _ := Generate()
	privateKeyPEM := PrivateKeyAsPEM(&privateKey)
	if len(privateKeyPEM) == 0 {
		t.Errorf("Expected private key PEM encoding to have length greater than 0, but got %d", len(privateKeyPEM))
	}
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		t.Errorf("Expected PEM block to be decoded, but got nil")
		return
	}
	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("Expected PEM block type to be 'RSA PRIVATE KEY', but got '%s'", block.Type)
	}
}

func TestPublicKeyAsPEM(t *testing.T) {
	privateKey, _ := Generate()
	publicKeyPEM := PublicKeyAsPEM(&privateKey)
	if len(publicKeyPEM) == 0 {
		t.Errorf("Expected public key PEM encoding to have length greater than 0, but got %d", len(publicKeyPEM))
	}
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		t.Errorf("Expected PEM block to be decoded, but got nil")
		return
	}
	if block.Type != "RSA PUBLIC KEY" {
		t.Errorf("Expected PEM block type to be 'RSA PUBLIC KEY', but got '%s'", block.Type)
	}
}

func TestSign(t *testing.T) {
	privateKey, _ := Generate()
	message := []byte("test message")
	signature := Sign(message, &privateKey)
	if len(signature) == 0 {
		t.Errorf("Expected signature to have length greater than 0, but got %d", len(signature))
	}
	err := Verify(message, signature, &privateKey)
	if err != nil {
		t.Errorf("Signature verification failed: %s", err)
	}
}

func TestVerify(t *testing.T) {
	privateKey, _ := Generate()
	message := []byte("test message")
	signature := Sign(message, &privateKey)

	err := Verify(message, signature, &privateKey)
	if err != nil {
		t.Errorf("Signature verification failed: %s", err)
	}
	t.Logf("Testing rejecting bad messages...")
	t.Logf("This should result in a failure")

	err = Verify([]byte("incorrect message"), signature, &privateKey)
	if err == nil {
		t.Errorf("Signature verification should have failed for incorrect message")
	}
	t.Logf("Testing rejecting bad signatures...")
	t.Logf("This should result in a failure")
	err = Verify(message, []byte("incorrect signature"), &privateKey)
	if err == nil {
		t.Errorf("Signature verification should have failed for incorrect signature")
	}
}

func TestEncrypt(t *testing.T) {
	privateKey, _ := Generate()
	message := []byte("test message")
	encryptedMessage := Encrypt(message, &privateKey)
	if len(encryptedMessage) == 0 {
		t.Errorf("Expected encrypted message to have length greater than 0, but got %d", len(encryptedMessage))
	}

}

func TestDecrypt(t *testing.T) {
	privateKey, _ := Generate()
	message := []byte("test message")
	encryptedMessage := Encrypt(message, &privateKey)
	decryptedMessage := Decrypt(encryptedMessage, &privateKey)
	if !bytes.Equal(message, decryptedMessage) {
		t.Errorf("Expected decrypted message to be equal to original message, but got %s", string(decryptedMessage))
	}

}

func TestEncryptDecrypt(t *testing.T) {
	privateKey, _ := Generate()
	message := []byte("test message")

	encryptedMessage := Encrypt(message, &privateKey)
	if len(encryptedMessage) == 0 {
		t.Errorf("Expected encrypted message to have length greater than 0, but got %d", len(encryptedMessage))
	}

	decryptedMessage := Decrypt(encryptedMessage, &privateKey)
	if !bytes.Equal(message, decryptedMessage) {
		t.Errorf("Expected decrypted message to be equal to original message, but got %s", string(decryptedMessage))
	}

	encryptedMessage = Encrypt(message, &privateKey)
	if len(encryptedMessage) == 0 {
		t.Errorf("Expected encrypted message to have length greater than 0, but got %d", len(encryptedMessage))
	}

	decryptedMessage = Decrypt(encryptedMessage, &privateKey)
	if !bytes.Equal(message, decryptedMessage) {
		t.Errorf("Expected decrypted message to be equal to original message, but got %s", string(decryptedMessage))
	}
}

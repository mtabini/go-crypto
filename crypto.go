// Package crypto provides a simple interface to AES encryption for Go.
//
// New keys can be generated using cryptographically secure random data by calling
// GenerateKey(), which returns keys large enough to support AES-256.
//
// A Provider (instantiated with NewProvider()) then provides and encryption and decryption
// services.
package crypto

// Interface Provider encrypts and decrypts arbitrary data using AES.
type Provider interface {
	// Encrypt generates an encrypted representation of its input, providing a randomly-generated
	// initialization vector. In output, the returned data is base64-encoded.
	Encrypt(source interface{}) (string, error)

	// MustEncrypt calls Encrypt and panics if an error is returned
	MustEncrypt(source interface{}) string

	// Decrypt decrypts input data encrypted by Encrypt
	Decrypt(string, interface{}) error
}

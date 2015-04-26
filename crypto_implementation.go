package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

type ProviderInstance struct {
	key []byte
}

// NewProvider creates a new provider
func NewProvider(key []byte) Provider {
	return &ProviderInstance{key}
}

// GenerateRandomString creates a cryptographically secure random string
func GenerateRandomString(length int) string {
	res := make([]byte, length/2)

	rand.Read(res)

	return hex.EncodeToString(res)
}

// GenerateKey creates a new AES-256 key using cryptographically secure random data
func GenerateKey() []byte {
	key := make([]byte, 32)

	rand.Read(key)

	return key
}

func (p *ProviderInstance) Encrypt(input interface{}) (string, error) {
	encoded, err := json.Marshal(input)

	if err != nil {
		return "", err
	}

	l := len(encoded) % aes.BlockSize

	if l > 0 {
		encoded = encoded[0:(len(encoded) + aes.BlockSize - l)]
	}

	encrypted := make([]byte, aes.BlockSize+len(encoded))

	iv := encrypted[:aes.BlockSize]

	rand.Read(iv)

	block, err := aes.NewCipher(p.key)

	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted[aes.BlockSize:], encoded)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (p *ProviderInstance) MustEncrypt(input interface{}) string {
	if res, err := p.Encrypt(input); err == nil {
		return res
	} else {
		panic(err)
	}
}

func (p *ProviderInstance) Decrypt(base64Source string, target interface{}) error {
	encrypted, err := base64.StdEncoding.DecodeString(base64Source)

	if err != nil {
		return err
	}

	if len(encrypted)%aes.BlockSize != 0 {
		return errors.New("Invalid encrypted data size.")
	}

	iv := encrypted[:aes.BlockSize]
	ciphertext := encrypted[aes.BlockSize:]

	block, err := aes.NewCipher(p.key)

	if err != nil {
		return err
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(ciphertext, ciphertext)

	err = json.Unmarshal(bytes.Trim(ciphertext, "\x00"), target)

	if err != nil {
		return err
	}

	return nil
}

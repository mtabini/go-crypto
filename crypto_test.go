package crypto

import (
	"testing"
)

type cryptoTestStruct struct {
	A int
	B string
}

func TestKey(t *testing.T) {
	k := GenerateKey()
	k1 := GenerateKey()

	if string(k) == string(k1) {
		t.Errorf("The key generator keeps returning the same key!")
	}
}

func TestRandom(t *testing.T) {
	r := GenerateRandomString(10)

	if len(r) != 10 {
		t.Errorf("The random generator returns strings of the wrong length")
	}
}

func TestCrypto(t *testing.T) {
	s := cryptoTestStruct{A: 1, B: "Test"}
	ss := cryptoTestStruct{}

	p := NewProvider(GenerateKey())

	e, err := p.Encrypt(s)

	if err != nil {
		t.Errorf("Unable to encrypt: %s", err)
	}

	err = p.Decrypt(e, &ss)

	if err != nil {
		t.Errorf("Unable to decrypt: %s", err)
	}

	if ss != s {
		t.Errorf("Encryption failed: expected %v, got %v instead", s, ss)
	}
}

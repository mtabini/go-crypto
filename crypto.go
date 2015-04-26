package crypto

type Provider interface {
	Encrypt(source interface{}) (string, error)
	MustEncrypt(source interface{}) string
	Decrypt(string, interface{}) error
}

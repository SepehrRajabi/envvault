package crypto

type ChaChaProvider struct{}

func (c *ChaChaProvider) AlgorithmID() string {
	return "chacha20poly1305"
}

func (c *ChaChaProvider) Encrypt(plaintext, password []byte) ([]byte, error) {
	// TODO: implementation
	return nil, nil
}

func (c *ChaChaProvider) Decrypt(payload, password []byte) ([]byte, error) {
	// TODO: implementation
	return nil, nil
}

func (c *ChaChaProvider) Description() ProviderInfo {
	return ProviderInfo{
		ID:          c.AlgorithmID(),
		Description: c.AlgorithmID(),
		Secure:      true,
	}
}

func init() {
	Register(&ChaChaProvider{})
}

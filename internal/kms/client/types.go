package client

// Certificate contains the private key and CA certificate stored under one
// KMS key ID.
type Certificate struct {
	PrivateKey []byte
	CACert     []byte
}

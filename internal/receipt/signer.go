package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jolovicdev/crawlwall/internal/config"
)

type Signer struct {
	enabled    bool
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewSigner(cfg config.ReceiptsConfig) (*Signer, error) {
	if !cfg.Enabled {
		return &Signer{}, nil
	}

	privateKey, publicKey, err := LoadPrivateKeyFile(cfg.Signer.KeyFile)
	if err != nil {
		return nil, err
	}

	return &Signer{
		enabled:    true,
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func (s *Signer) Enabled() bool {
	return s != nil && s.enabled
}

func (s *Signer) Sign(payload Payload) (Envelope, error) {
	if !s.Enabled() {
		return Envelope{}, fmt.Errorf("receipt signer is disabled")
	}

	envelope := Envelope{
		ReceiptID: newReceiptID(),
		Payload:   payload,
	}

	data, err := CanonicalEnvelopeBytes(envelope)
	if err != nil {
		return Envelope{}, err
	}

	sig := ed25519.Sign(s.privateKey, data)
	envelope.Signature = base64.StdEncoding.EncodeToString(sig)
	return envelope, nil
}

func VerifyEnvelope(publicKey ed25519.PublicKey, envelope Envelope) error {
	data, err := CanonicalEnvelopeBytes(envelope)
	if err != nil {
		return err
	}

	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(publicKey, data, signature) {
		return fmt.Errorf("invalid receipt signature")
	}
	return nil
}

func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("private key file is not valid PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not ed25519")
	}

	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("derived public key is not ed25519")
	}

	return privateKey, publicKey, nil
}

func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("public key file is not valid PEM")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ed25519")
	}
	return publicKey, nil
}

func GenerateKeyPairFiles(privatePath, publicPath string) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key pair: %w", err)
	}

	privatePEM, err := MarshalPrivateKeyPEM(privateKey)
	if err != nil {
		return err
	}

	publicPEM, err := MarshalPublicKeyPEM(publicKey)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(privatePath), 0o755); err != nil {
		return fmt.Errorf("create private key directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(publicPath), 0o755); err != nil {
		return fmt.Errorf("create public key directory: %w", err)
	}

	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(publicPath, publicPEM, 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	return nil
}

func MarshalPrivateKeyPEM(privateKey ed25519.PrivateKey) ([]byte, error) {
	privateBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateBytes}), nil
}

func MarshalPublicKeyPEM(publicKey ed25519.PublicKey) ([]byte, error) {
	publicBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes}), nil
}

func newReceiptID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

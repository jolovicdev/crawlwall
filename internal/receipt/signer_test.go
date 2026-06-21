package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/jolovicdev/crawlwall/internal/config"
)

func samplePayload() Payload {
	return Payload{
		Version: "crawlwall.receipt/v1",
		EventID: "evt_abc",
		SiteID:  "site",
		Time:    "2026-01-01T00:00:00Z",
		Bot:     BotPayload{ID: "gptbot", Class: "ai_training", Verified: true},
		Request: RequestPayload{Host: "example.com", Method: "GET", Path: "/archive/a"},
		Policy:  PolicyPayload{RuleID: "meter", Action: "allow_metered"},
		Metering: &MeteringPayload{
			Amount:   0.002,
			Currency: "USD",
			Unit:     "request",
		},
	}
}

func newTestSigner(t *testing.T) (*Signer, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	privPath := filepath.Join(dir, "crawlwall.key")
	pubPath := filepath.Join(dir, "crawlwall.pub")
	if err := GenerateKeyPairFiles(privPath, pubPath); err != nil {
		t.Fatalf("GenerateKeyPairFiles() error = %v", err)
	}

	signer, err := NewSigner(config.ReceiptsConfig{
		Enabled: true,
		Signer:  config.SignerConfig{Type: "ed25519", KeyFile: privPath},
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	publicKey, err := LoadPublicKeyFile(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKeyFile() error = %v", err)
	}
	return signer, publicKey
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	signer, publicKey := newTestSigner(t)

	envelope, err := signer.Sign(samplePayload())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if envelope.ReceiptID == "" || envelope.Signature == "" {
		t.Fatalf("envelope missing id or signature: %+v", envelope)
	}
	if err := VerifyEnvelope(publicKey, envelope); err != nil {
		t.Fatalf("VerifyEnvelope() error = %v", err)
	}
}

func TestVerifyRejectsTamperedFields(t *testing.T) {
	signer, publicKey := newTestSigner(t)
	envelope, err := signer.Sign(samplePayload())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	tampers := map[string]func(*Envelope){
		"path":     func(e *Envelope) { e.Payload.Request.Path = "/different" },
		"action":   func(e *Envelope) { e.Payload.Policy.Action = "allow" },
		"verified": func(e *Envelope) { e.Payload.Bot.Verified = false },
		"amount":   func(e *Envelope) { e.Payload.Metering.Amount = 9.99 },
		"event_id": func(e *Envelope) { e.Payload.EventID = "evt_other" },
		"receipt":  func(e *Envelope) { e.ReceiptID = "tampered-" + e.ReceiptID },
	}

	for name, tamper := range tampers {
		tampered := envelope
		if tampered.Payload.Metering != nil {
			metering := *tampered.Payload.Metering
			tampered.Payload.Metering = &metering
		}
		tamper(&tampered)
		if err := VerifyEnvelope(publicKey, tampered); err == nil {
			t.Fatalf("VerifyEnvelope() error = nil for tampered %s", name)
		}
	}
}

func TestVerifyRejectsBadSignature(t *testing.T) {
	signer, publicKey := newTestSigner(t)
	envelope, err := signer.Sign(samplePayload())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	wrongSig := envelope
	wrongSig.Signature = base64.StdEncoding.EncodeToString([]byte("this is not a real signature."))
	if err := VerifyEnvelope(publicKey, wrongSig); err == nil {
		t.Fatalf("VerifyEnvelope() error = nil for replaced signature")
	}

	malformed := envelope
	malformed.Signature = "!!! not base64 !!!"
	if err := VerifyEnvelope(publicKey, malformed); err == nil {
		t.Fatalf("VerifyEnvelope() error = nil for malformed signature")
	}
}

func TestVerifyRejectsWrongPublicKey(t *testing.T) {
	signer, _ := newTestSigner(t)
	envelope, err := signer.Sign(samplePayload())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if err := VerifyEnvelope(otherPublic, envelope); err == nil {
		t.Fatalf("VerifyEnvelope() error = nil with an unrelated public key")
	}
}

func TestNewSignerDisabledWhenReceiptsOff(t *testing.T) {
	signer, err := NewSigner(config.ReceiptsConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	if signer.Enabled() {
		t.Fatalf("signer should be disabled when receipts are off")
	}
	if _, err := signer.Sign(samplePayload()); err == nil {
		t.Fatalf("disabled signer Sign() error = nil, want error")
	}
}

func TestNewSignerMissingKeyFileFails(t *testing.T) {
	_, err := NewSigner(config.ReceiptsConfig{
		Enabled: true,
		Signer:  config.SignerConfig{Type: "ed25519", KeyFile: filepath.Join(t.TempDir(), "absent.key")},
	})
	if err == nil {
		t.Fatalf("NewSigner() error = nil for missing key file")
	}
}

func TestLoadPrivateKeyRejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(path, []byte("not a pem block"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, _, err := LoadPrivateKeyFile(path); err == nil {
		t.Fatalf("LoadPrivateKeyFile() error = nil for invalid PEM")
	}
}

func TestCanonicalEnvelopeBytesAreStableAndExcludeSignature(t *testing.T) {
	envelope := Envelope{ReceiptID: "rid", Payload: samplePayload()}

	first, err := CanonicalEnvelopeBytes(envelope)
	if err != nil {
		t.Fatalf("CanonicalEnvelopeBytes() error = %v", err)
	}
	second, err := CanonicalEnvelopeBytes(envelope)
	if err != nil {
		t.Fatalf("CanonicalEnvelopeBytes() error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical bytes are not deterministic")
	}

	withSig := envelope
	withSig.Signature = "should-not-matter"
	third, err := CanonicalEnvelopeBytes(withSig)
	if err != nil {
		t.Fatalf("CanonicalEnvelopeBytes() error = %v", err)
	}
	if !bytes.Equal(first, third) {
		t.Fatalf("the signature field must not affect canonical bytes")
	}
}

package receipt

import "encoding/json"

type Payload struct {
	Version  string           `json:"version"`
	EventID  string           `json:"event_id"`
	SiteID   string           `json:"site_id"`
	Time     string           `json:"time"`
	Bot      BotPayload       `json:"bot"`
	Request  RequestPayload   `json:"request"`
	Policy   PolicyPayload    `json:"policy"`
	Metering *MeteringPayload `json:"metering,omitempty"`
}

type BotPayload struct {
	ID       string `json:"id"`
	Class    string `json:"class"`
	Verified bool   `json:"verified"`
}

type RequestPayload struct {
	Host   string `json:"host"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

type PolicyPayload struct {
	RuleID string `json:"rule_id"`
	Action string `json:"action"`
}

type MeteringPayload struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
	Unit     string  `json:"unit"`
}

type Envelope struct {
	ReceiptID string  `json:"receipt_id"`
	Payload   Payload `json:"payload"`
	Signature string  `json:"signature"`
}

// Receipt payloads intentionally use only structs, strings, numbers, booleans,
// and slices. Do not add map fields without replacing json.Marshal with a
// canonical sorted encoder, or old signatures may stop verifying.
func CanonicalBytes(payload Payload) ([]byte, error) {
	return json.Marshal(payload)
}

func CanonicalEnvelopeBytes(envelope Envelope) ([]byte, error) {
	return json.Marshal(struct {
		ReceiptID string  `json:"receipt_id"`
		Payload   Payload `json:"payload"`
	}{
		ReceiptID: envelope.ReceiptID,
		Payload:   envelope.Payload,
	})
}

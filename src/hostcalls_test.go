package main

import (
	"encoding/json"
	"testing"
)

func TestMarshalHostPayloadPassesThroughRawJSONBytes(t *testing.T) {
	raw := []byte(`{"Method":"GET","URL":"https://example.invalid/v1/models"}`)
	got, err := marshalHostPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("payload = %s, want %s", got, raw)
	}
}

func TestMarshalHostPayloadPassesThroughRawMessage(t *testing.T) {
	raw := json.RawMessage(`{"StreamID":"abc"}`)
	got, err := marshalHostPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("payload = %s, want %s", got, raw)
	}
}

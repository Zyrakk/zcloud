package api

import "testing"

func TestGenerateDeviceID(t *testing.T) {
	id := generateDeviceID("test-public-key")
	if len(id) != 12 {
		t.Errorf("expected 12-char ID, got %d: %s", len(id), id)
	}
	if id2 := generateDeviceID("test-public-key"); id != id2 {
		t.Error("generateDeviceID not deterministic")
	}
}

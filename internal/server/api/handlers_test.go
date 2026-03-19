package api

import "testing"

func TestHashToken(t *testing.T) {
	h1 := hashToken("test-token")
	h2 := hashToken("test-token")
	if h1 != h2 {
		t.Error("hashToken not deterministic")
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-char hex hash, got %d: %s", len(h1), h1)
	}
	if h1 == hashToken("different-token") {
		t.Error("different inputs produced same hash")
	}
}

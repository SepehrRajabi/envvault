package crypto

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestEncodeDecodeShareRoundTrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	t.Setenv("AGE_IDENTITY", identity.String())

	vars := map[string]string{"API_KEY": "abc123", "DB_URL": "postgres://localhost"}

	encoded, err := EncodeShare(vars, identity.Recipient().String(), 0)
	if err != nil {
		t.Fatalf("EncodeShare: %v", err)
	}
	if !strings.HasPrefix(encoded, SharePrefix) {
		t.Fatalf("expected encoded share to start with %q, got %q", SharePrefix, encoded)
	}

	decoded, err := DecodeShare(encoded)
	if err != nil {
		t.Fatalf("DecodeShare: %v", err)
	}
	if !reflect.DeepEqual(decoded, vars) {
		t.Fatalf("expected %v, got %v", vars, decoded)
	}
}

func TestDecodeShareFailsWithoutMatchingIdentity(t *testing.T) {
	recipientIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}

	encoded, err := EncodeShare(map[string]string{"K": "v"}, recipientIdentity.Recipient().String(), 0)
	if err != nil {
		t.Fatalf("EncodeShare: %v", err)
	}

	// Point AGE_IDENTITY at an unrelated key, simulating someone who
	// intercepted the share string but isn't the intended recipient.
	otherIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	t.Setenv("AGE_IDENTITY", otherIdentity.String())

	if _, err := DecodeShare(encoded); err == nil {
		t.Fatal("expected decode to fail for a non-matching identity")
	}
}

func TestDecodeShareRejectsExpiredPayload(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	t.Setenv("AGE_IDENTITY", identity.String())

	encoded, err := EncodeShare(map[string]string{"K": "v"}, identity.Recipient().String(), 1)
	if err != nil {
		t.Fatalf("EncodeShare: %v", err)
	}

	time.Sleep(2100 * time.Millisecond)

	if _, err := DecodeShare(encoded); err == nil {
		t.Fatal("expected decode to fail for an expired payload")
	}
}

func TestDecodeShareRejectsMalformedInput(t *testing.T) {
	if _, err := DecodeShare("not-a-share-string"); err == nil {
		t.Fatal("expected error for input missing evlt:// prefix")
	}
	if _, err := DecodeShare(SharePrefix + "not-valid-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
}

func TestEncodeShareRejectsEmptyVariables(t *testing.T) {
	if _, err := EncodeShare(nil, "age1anything", 0); err == nil {
		t.Fatal("expected error for empty variables map")
	}
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		key, pattern string
		want         bool
	}{
		{"DB_URL", "*", true},
		{"DB_URL", "DB_URL", true},
		{"DB_URL", "DB_*", true},
		{"DB_URL", "API_*", false},
		{"DB_URL", "DB_URLX", false},
	}
	for _, tt := range tests {
		if got := matchesPattern(tt.key, tt.pattern); got != tt.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.key, tt.pattern, got, tt.want)
		}
	}
}

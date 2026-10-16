package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func wrapShare(t *testing.T, envelope []byte, outer SharedPayload) string {
	t.Helper()
	outer.Data = base64.StdEncoding.EncodeToString(envelope)
	j, _ := json.Marshal(outer)
	return SharePrefix + base64.StdEncoding.EncodeToString(j)
}

// A share encrypted with a password-less algorithm (no knowledge of the
// recipient's key) must be rejected.
func TestDecodeShareRejectsForgedAlgorithm(t *testing.T) {
	vars, _ := json.Marshal(map[string]string{"PATH": "/tmp/evil"})
	for _, alg := range []string{"aes256gcm-pbkdf2", "aes256gcm-argon2id"} {
		p, err := GetProvider(alg)
		if err != nil {
			t.Fatal(err)
		}
		enc, err := Encrypt(vars, []byte(""), p)
		if err != nil {
			t.Fatal(err)
		}
		_, err = DecodeShare(wrapShare(t, enc, SharedPayload{Algorithm: "age-pubkey"}))
		if err == nil || !strings.Contains(err.Error(), "expected algorithm age-pubkey") {
			t.Errorf("%s: forged share accepted or wrong error: %v", alg, err)
		}
	}
}

func TestShareRoundTripAndAuthenticatedExpiry(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	t.Setenv("AGE_IDENTITY", id.String())

	s, err := EncodeShare(map[string]string{"A": "1"}, id.Recipient().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeShare(s)
	if err != nil || got["A"] != "1" {
		t.Fatalf("round trip: %v, %v", got, err)
	}

	// Expired share: inner expiry is enforced.
	expired, err := EncodeShare(map[string]string{"A": "1"}, id.Recipient().String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond)
	if _, err := DecodeShare(expired); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}

	// Relay strips/extends the outer expires_at: still expired.
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(expired, SharePrefix))
	var outer SharedPayload
	json.Unmarshal(raw, &outer)
	outer.ExpiresAt = time.Now().Add(time.Hour).Unix()
	j, _ := json.Marshal(outer)
	tampered := SharePrefix + base64.StdEncoding.EncodeToString(j)
	if _, err := DecodeShare(tampered); err == nil {
		t.Fatal("outer expires_at override bypassed the authenticated expiry")
	}
}

func TestShareDoesNotEmbedCommitMetadata(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	s, err := EncodeShare(map[string]string{"A": "1"}, id.Recipient().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, SharePrefix))
	var outer SharedPayload
	json.Unmarshal(raw, &outer)
	env, _ := base64.StdEncoding.DecodeString(outer.Data)
	h, _, err := parseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	if h.Commit != nil {
		t.Fatalf("share header leaks commit metadata: %+v", h.Commit)
	}
}

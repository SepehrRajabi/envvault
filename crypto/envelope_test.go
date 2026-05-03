package crypto

import (
	"encoding/json"
	"testing"
)

func TestEnvelopeHeaderCommitMetadataMarshal(t *testing.T) {
	hdr := envelopeHeader{
		Version:   currentVersion,
		Algorithm: "test-algo",
		Checksum:  "deadbeef",
		Commit: &GitCommitMetadata{
			Hash:            "abc123",
			SignatureStatus: "G",
			SignerKey:       "0123456789abcdef",
			Signer:          "alice@example.com",
			Author:          "Alice <alice@example.com>",
		},
	}

	data, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal envelope header: %v", err)
	}

	var decoded envelopeHeader
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal envelope header: %v", err)
	}

	if decoded.Commit == nil {
		t.Fatal("expected commit metadata after unmarshal")
	}
	if decoded.Commit.Hash != hdr.Commit.Hash {
		t.Fatalf("expected hash %q, got %q", hdr.Commit.Hash, decoded.Commit.Hash)
	}
	if decoded.Commit.SignatureStatus != hdr.Commit.SignatureStatus {
		t.Fatalf("expected signature status %q, got %q", hdr.Commit.SignatureStatus, decoded.Commit.SignatureStatus)
	}
}

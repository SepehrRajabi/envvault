package crypto

import (
	"bytes"
	"testing"
)

func TestSplitCombineRoundTrip(t *testing.T) {
	secret := []byte("correct horse battery staple")

	shares, err := SplitSecretToBase64(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecretToBase64: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	got, err := CombineSecretFromBase64(shares[:3])
	if err != nil {
		t.Fatalf("CombineSecretFromBase64: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("expected %q, got %q", secret, got)
	}
}

func TestCombineAnyThresholdSubsetReconstructs(t *testing.T) {
	secret := []byte("subset-independence")

	shares, err := SplitSecretToBase64(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecretToBase64: %v", err)
	}

	subsets := [][]string{
		{shares[0], shares[1], shares[2]},
		{shares[1], shares[2], shares[3]},
		{shares[0], shares[2], shares[4]},
		{shares[2], shares[3], shares[4]},
	}
	for i, subset := range subsets {
		got, err := CombineSecretFromBase64(subset)
		if err != nil {
			t.Fatalf("subset %d: CombineSecretFromBase64: %v", i, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("subset %d: expected %q, got %q", i, secret, got)
		}
	}
}

func TestCombineBelowThresholdDoesNotReconstruct(t *testing.T) {
	secret := []byte("needs-three-shares")

	shares, err := SplitSecretToBase64(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitSecretToBase64: %v", err)
	}

	got, err := CombineSecretFromBase64(shares[:2])
	if err != nil {
		t.Fatalf("CombineSecretFromBase64 with 2 shares: %v", err)
	}
	// Reconstruction with fewer than the threshold "succeeds" mechanically
	// (the math doesn't know the threshold) but must not yield the secret.
	if bytes.Equal(got, secret) {
		t.Fatal("expected reconstruction from below-threshold shares to fail to recover the secret")
	}
}

func TestSplitSecretInvalidParams(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
		n, k   int
	}{
		{"threshold too low", []byte("s"), 5, 1},
		{"shares less than threshold", []byte("s"), 2, 3},
		{"empty secret", []byte(""), 5, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := SplitSecretToBase64(tt.secret, tt.n, tt.k); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestCombineSharesErrors(t *testing.T) {
	secret := []byte("duplicate-x-detection")
	shares, err := SplitSecretToBase64(secret, 3, 2)
	if err != nil {
		t.Fatalf("SplitSecretToBase64: %v", err)
	}

	t.Run("no shares", func(t *testing.T) {
		if _, err := CombineSecretFromBase64(nil); err == nil {
			t.Fatal("expected error for no shares")
		}
	})

	t.Run("single share", func(t *testing.T) {
		if _, err := CombineSecretFromBase64(shares[:1]); err == nil {
			t.Fatal("expected error for a single share")
		}
	})

	t.Run("duplicate share", func(t *testing.T) {
		if _, err := CombineSecretFromBase64([]string{shares[0], shares[0]}); err == nil {
			t.Fatal("expected error for duplicate share x-coordinate")
		}
	})

	t.Run("inconsistent lengths", func(t *testing.T) {
		other, err := SplitSecretToBase64([]byte("a different, longer secret"), 3, 2)
		if err != nil {
			t.Fatalf("SplitSecretToBase64: %v", err)
		}
		if _, err := CombineSecretFromBase64([]string{shares[0], other[1]}); err == nil {
			t.Fatal("expected error for mismatched share lengths")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		if _, err := CombineSecretFromBase64([]string{"not-valid-base64!!!", shares[1]}); err == nil {
			t.Fatal("expected error for invalid base64 share")
		}
	})
}

func TestGFArithmeticIdentities(t *testing.T) {
	for a := 1; a < 256; a++ {
		x := byte(a)
		if got := gfMul(x, gfInv(x)); got != 1 {
			t.Fatalf("gfMul(%d, gfInv(%d)) = %d, want 1", x, x, got)
		}
		if got := gfDiv(x, x); got != 1 {
			t.Fatalf("gfDiv(%d, %d) = %d, want 1", x, x, got)
		}
	}
	if got := gfInv(0); got != 0 {
		t.Fatalf("gfInv(0) = %d, want 0", got)
	}
	if got := gfMul(0, 42); got != 0 {
		t.Fatalf("gfMul(0, 42) = %d, want 0", got)
	}
}

func TestShamirAESGCMProviderEncryptDecryptRoundTrip(t *testing.T) {
	p := &ShamirAESGCMProvider{
		ID:        "shamir-aes256gcm",
		Time:      1,
		Memory:    8 * 1024,
		Threads:   1,
		SaltLen:   16,
		NonceLen:  12,
		Shares:    5,
		Threshold: 3,
	}

	plaintext := []byte("KEY=super-secret-value\n")
	ciphertext, err := p.Encrypt(plaintext, []byte("ignored-password-placeholder"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	shares := p.GeneratedShares()
	if len(shares) != 5 {
		t.Fatalf("expected 5 generated shares, got %d", len(shares))
	}

	sharesInput := []byte(shares[0] + "," + shares[1] + "," + shares[2])
	got, err := p.Decrypt(ciphertext, sharesInput)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, got)
	}
}

func TestShamirAESGCMProviderDecryptInsufficientShares(t *testing.T) {
	p := &ShamirAESGCMProvider{
		ID:        "shamir-aes256gcm",
		Time:      1,
		Memory:    8 * 1024,
		Threads:   1,
		SaltLen:   16,
		NonceLen:  12,
		Shares:    5,
		Threshold: 3,
	}

	ciphertext, err := p.Encrypt([]byte("data"), []byte("placeholder"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	shares := p.GeneratedShares()
	sharesInput := []byte(shares[0] + "," + shares[1])
	if _, err := p.Decrypt(ciphertext, sharesInput); err == nil {
		t.Fatal("expected decrypt with fewer than threshold shares to fail")
	}
}

func TestShamirAESGCMProviderEncryptRejectsEmptyPassword(t *testing.T) {
	p := &ShamirAESGCMProvider{Threshold: 3, Shares: 5}
	if _, err := p.Encrypt([]byte("data"), nil); err != ErrorNonEmptySecret {
		t.Fatalf("expected ErrorNonEmptySecret, got %v", err)
	}
}

func TestShamirAESGCMProviderEncryptRejectsInvalidThresholdAndShares(t *testing.T) {
	t.Run("threshold too low", func(t *testing.T) {
		p := &ShamirAESGCMProvider{Threshold: 1, Shares: 5}
		if _, err := p.Encrypt([]byte("data"), []byte("pw")); err == nil {
			t.Fatal("expected error for threshold < 2")
		}
	})
	t.Run("shares below threshold", func(t *testing.T) {
		p := &ShamirAESGCMProvider{Threshold: 3, Shares: 2}
		if _, err := p.Encrypt([]byte("data"), []byte("pw")); err == nil {
			t.Fatal("expected error for shares < threshold")
		}
	})
}

func TestShamirAESGCMProviderDecryptRejectsCorruptPayload(t *testing.T) {
	p := &ShamirAESGCMProvider{
		ID:        "shamir-aes256gcm",
		Time:      1,
		Memory:    8 * 1024,
		Threads:   1,
		SaltLen:   16,
		NonceLen:  12,
		Shares:    5,
		Threshold: 3,
	}

	t.Run("too small", func(t *testing.T) {
		if _, err := p.Decrypt([]byte{1, 2}, []byte("share1,share2,share3")); err != ErrorPayloadTooSmall {
			t.Fatalf("expected ErrorPayloadTooSmall, got %v", err)
		}
	})

	t.Run("bad version", func(t *testing.T) {
		payload := []byte{99, 3, 16, 12, 0, 0, 0, 0}
		if _, err := p.Decrypt(payload, []byte("share1,share2,share3")); err == nil {
			t.Fatal("expected error for unsupported payload version")
		}
	})

	t.Run("no shares provided", func(t *testing.T) {
		ciphertext, err := p.Encrypt([]byte("data"), []byte("placeholder"))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if _, err := p.Decrypt(ciphertext, []byte("")); err != ErrorNoSharesProvided {
			t.Fatalf("expected ErrorNoSharesProvided, got %v", err)
		}
	})
}

func TestDecodeShamirPayloadThreshold(t *testing.T) {
	p := &ShamirAESGCMProvider{
		ID:        "shamir-aes256gcm",
		Time:      1,
		Memory:    8 * 1024,
		Threads:   1,
		SaltLen:   16,
		NonceLen:  12,
		Shares:    5,
		Threshold: 4,
	}

	ciphertext, err := p.Encrypt([]byte("data"), []byte("placeholder"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Build a fake envelope: [version:1][hdrLen:4 BE][header bytes][shamir payload]
	envelopeHdr := []byte("fake-header-bytes")
	data := make([]byte, 0, 5+len(envelopeHdr)+len(ciphertext))
	data = append(data, 1) // envelope version, unused by DecodeShamirPayloadThreshold
	hdrLen := len(envelopeHdr)
	data = append(data, byte(hdrLen>>24), byte(hdrLen>>16), byte(hdrLen>>8), byte(hdrLen))
	data = append(data, envelopeHdr...)
	data = append(data, ciphertext...)

	threshold, err := DecodeShamirPayloadThreshold(data)
	if err != nil {
		t.Fatalf("DecodeShamirPayloadThreshold: %v", err)
	}
	if threshold != 4 {
		t.Fatalf("expected threshold 4, got %d", threshold)
	}
}

func TestDecodeShamirPayloadThresholdRejectsTruncatedData(t *testing.T) {
	if _, err := DecodeShamirPayloadThreshold([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for truncated header")
	}
}

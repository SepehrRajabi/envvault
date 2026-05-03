package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestQuorumStateSaveLoad(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "example.env.vault")
	if err := os.WriteFile(vaultPath, []byte("data"), 0600); err != nil {
		t.Fatalf("write vault file: %v", err)
	}

	statePath, err := quorumStatePath(vaultPath)
	if err != nil {
		t.Fatalf("quorumStatePath: %v", err)
	}

	state := &quorumState{
		VaultPath:   vaultPath,
		PayloadHash: "deadbeef",
		Threshold:   2,
		Shares:      []string{"share1", "share2"},
	}

	if err := saveQuorumState(statePath, state); err != nil {
		t.Fatalf("saveQuorumState: %v", err)
	}

	loaded, err := loadQuorumState(statePath)
	if err != nil {
		t.Fatalf("loadQuorumState: %v", err)
	}

	if !reflect.DeepEqual(state, loaded) {
		t.Fatalf("expected loaded state %+v, got %+v", state, loaded)
	}
}

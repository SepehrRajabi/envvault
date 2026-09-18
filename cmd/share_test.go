package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadFiltersFromFileSkipsBlankAndComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vars.txt")
	content := "API_KEY\n\n# a comment\n  DB_URL  \n#another\nTOKEN\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write vars file: %v", err)
	}

	filters, err := readFiltersFromFile(path)
	if err != nil {
		t.Fatalf("readFiltersFromFile: %v", err)
	}

	want := []string{"API_KEY", "DB_URL", "TOKEN"}
	if !reflect.DeepEqual(filters, want) {
		t.Fatalf("unexpected filters: got %v, want %v", filters, want)
	}
}

func TestReadFiltersFromFileMissing(t *testing.T) {
	if _, err := readFiltersFromFile(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Fatal("expected error for missing filters file")
	}
}

func TestShortenPublicKey(t *testing.T) {
	long := "age1e4j88gcaxfudjk6xtgskvyrl3j5e9rkzevx9h4m4xyn2d8gn9d4swlx0fv"
	got := shortenPublicKey(long)
	if got != "age1e4j88g..."+long[len(long)-10:] {
		t.Fatalf("unexpected shortened key: %q", got)
	}

	short := "age1short"
	if shortenPublicKey(short) != short {
		t.Fatalf("expected short key returned unchanged, got %q", shortenPublicKey(short))
	}
}

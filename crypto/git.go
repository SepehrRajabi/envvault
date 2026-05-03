package crypto

import (
	"os/exec"
	"strings"
)

type GitCommitMetadata struct {
	Hash            string `json:"hash,omitempty"`
	SignatureStatus string `json:"signature_status,omitempty"`
	SignerKey       string `json:"signer_key,omitempty"`
	Signer          string `json:"signer,omitempty"`
	Author          string `json:"author,omitempty"`
}

func GetGitCommitMetadata() (*GitCommitMetadata, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, nil
	}

	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}
	if strings.TrimSpace(string(out)) != "true" {
		return nil, nil
	}

	cmd = exec.Command("git", "log", "-1", "--pretty=format:%H%n%G?%n%GK%n%GS%n%aN <%aE>")
	out, err = cmd.Output()
	if err != nil {
		return nil, nil
	}

	lines := strings.SplitN(strings.TrimRight(string(out), "\n"), "\n", 5)
	if len(lines) < 5 {
		return nil, nil
	}

	return &GitCommitMetadata{
		Hash:            strings.TrimSpace(lines[0]),
		SignatureStatus: strings.TrimSpace(lines[1]),
		SignerKey:       strings.TrimSpace(lines[2]),
		Signer:          strings.TrimSpace(lines[3]),
		Author:          strings.TrimSpace(lines[4]),
	}, nil
}

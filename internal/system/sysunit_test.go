package system_test

import (
	"strings"
	"testing"

	"github.com/greboid/compose-sops/internal/system"
)

func TestGenerateDefaultLayout(t *testing.T) {
	unit := system.GenerateUnit("/etc/compose-sops/key.cred", "compose-sops-key", system.RuntimeKey)
	checks := map[string]string{
		"quoted decrypt command": "/usr/bin/systemd-creds decrypt --name=\"compose-sops-key\" \"/etc/compose-sops/key.cred\" \"/run/compose-sops/age-key.txt\"",
		"runtime directory":      "RuntimeDirectory=compose-sops",
		"runtime directory mode": "RuntimeDirectoryMode=0700",
		"umask":                  "UMask=0077",
		"oneshot + remain":       "Type=oneshot\nRemainAfterExit=yes",
		"install target":         "WantedBy=multi-user.target",
		"tpm setup ordering":     "After=systemd-tpm2-setup.service",
		"documentation link":     "Documentation=man:systemd-creds(1)",
	}
	for name, want := range checks {
		if !strings.Contains(unit, want) {
			t.Fatalf("%s: unit missing %q:\n%s", name, want, unit)
		}
	}
}

func TestGenerateFallsBackToDefaultRuntimeDir(t *testing.T) {
	unit := system.GenerateUnit("/k.cred", "name", "/var/lib/other/key.txt")
	if !strings.Contains(unit, "RuntimeDirectory=compose-sops") {
		t.Fatalf("unit should keep the default runtime directory for non-/run key paths:\n%s", unit)
	}
}

func TestGenerateUsesKeyPathParentUnderRun(t *testing.T) {
	unit := system.GenerateUnit("/k.cred", "name", "/run/mysvc/identity.txt")
	if !strings.Contains(unit, "RuntimeDirectory=mysvc") {
		t.Fatalf("expected RuntimeDirectory=mysvc:\n%s", unit)
	}
	if !strings.Contains(unit, `decrypt --name="name" "/k.cred" "/run/mysvc/identity.txt"`) {
		t.Fatalf("decrypt command wrong:\n%s", unit)
	}
}

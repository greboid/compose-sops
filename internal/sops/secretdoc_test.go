package sops_test

import (
	"strings"
	"testing"

	sopsv3 "github.com/getsops/sops/v3"

	"github.com/greboid/compose-sops/internal/sops"
)

func branch(pairs ...any) sopsv3.TreeBranch {
	var b sopsv3.TreeBranch
	for i := 0; i < len(pairs); i += 2 {
		b = append(b, sopsv3.TreeItem{Key: pairs[i], Value: pairs[i+1]})
	}
	return b
}

func TestValidateFlatAcceptsStrings(t *testing.T) {
	secrets, err := sops.ValidateFlat(
		sopsv3.TreeBranches{branch("api_key", "abc", "db_password", "hunter2 ")},
		sops.DefaultLimits,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 || secrets[0].Name != "api_key" || secrets[0].Value != "abc" {
		t.Fatalf("unexpected result: %+v", secrets)
	}
}

func TestValidateFlatSkipsComments(t *testing.T) {
	b := sopsv3.TreeBranch{
		{Key: sopsv3.Comment{Value: "a comment"}, Value: nil},
		{Key: "api_key", Value: "abc"},
	}
	secrets, err := sops.ValidateFlat(sopsv3.TreeBranches{b}, sops.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 {
		t.Fatalf("comments not skipped: %+v", secrets)
	}
}

func TestValidateFlatRejectsDuplicates(t *testing.T) {
	_, err := sops.ValidateFlat(
		sopsv3.TreeBranches{branch("api_key", "one", "api_key", "two")},
		sops.DefaultLimits,
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate accepted: %v", err)
	}
}

func TestValidateFlatRejectsNested(t *testing.T) {
	_, err := sops.ValidateFlat(
		sopsv3.TreeBranches{branch("db", sopsv3.TreeBranch{{Key: "pw", Value: "x"}})},
		sops.DefaultLimits,
	)
	if err == nil || !strings.Contains(err.Error(), "nested mapping") {
		t.Fatalf("nested accepted: %v", err)
	}
}

func TestValidateFlatRejectsSequences(t *testing.T) {
	_, err := sops.ValidateFlat(
		sopsv3.TreeBranches{branch("list", []any{"a"})},
		sops.DefaultLimits,
	)
	if err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("sequence accepted: %v", err)
	}
}

func TestValidateFlatRejectsNonStringScalars(t *testing.T) {
	for _, v := range []any{int(8080), 1.5, true, nil} {
		_, err := sops.ValidateFlat(
			sopsv3.TreeBranches{branch("key", v)},
			sops.DefaultLimits,
		)
		if err == nil || !strings.Contains(err.Error(), "must be YAML strings") {
			t.Fatalf("non-string %T accepted: %v", v, err)
		}
	}
}

func TestValidateFlatRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", "..", ".", ".hidden", "-dash", "with space", "with/slash", "with\nnewline", strings.Repeat("a", 129)} {
		_, err := sops.ValidateFlat(
			sopsv3.TreeBranches{branch(name, "v")},
			sops.DefaultLimits,
		)
		if err == nil {
			t.Fatalf("name %q accepted", name)
		}
	}
	for _, name := range []string{"a", "A_9", "a.b-c_d", strings.Repeat("a", 128)} {
		if _, err := sops.ValidateFlat(
			sopsv3.TreeBranches{branch(name, "v")},
			sops.DefaultLimits,
		); err != nil {
			t.Fatalf("name %q rejected: %v", name, err)
		}
	}
}

func TestValidateFlatRejectsNUL(t *testing.T) {
	_, err := sops.ValidateFlat(
		sopsv3.TreeBranches{branch("key", "a\x00b")},
		sops.DefaultLimits,
	)
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("NUL accepted: %v", err)
	}
}

func TestValidateFlatEnforcesSizeLimits(t *testing.T) {
	_, err := sops.ValidateFlat(
		sopsv3.TreeBranches{branch("key", strings.Repeat("x", 64<<10+1))},
		sops.DefaultLimits,
	)
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized value accepted: %v", err)
	}
}

func TestValidateFlatRejectsMultiDocument(t *testing.T) {
	_, err := sops.ValidateFlat(
		sopsv3.TreeBranches{branch("a", "1"), branch("b", "2")},
		sops.DefaultLimits,
	)
	if err == nil || !strings.Contains(err.Error(), "one YAML document") {
		t.Fatalf("multi-document accepted: %v", err)
	}
}

func TestValidateFlatRejectsEmpty(t *testing.T) {
	_, err := sops.ValidateFlat(sopsv3.TreeBranches{branch()}, sops.DefaultLimits)
	if err == nil || !strings.Contains(err.Error(), "no secrets") {
		t.Fatalf("empty document accepted: %v", err)
	}
}

func TestValidateFlatNeverQuotesValues(t *testing.T) {
	secretValue := "TOPSECRETVALUE"
	_, err := sops.ValidateFlat(
		sopsv3.TreeBranches{branch("key", 42)},
		sops.DefaultLimits,
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatalf("error contains value: %v", err)
	}
}

package tools

import (
	"strings"
	"testing"
)

func TestContainmentRunnerRejectsArbitraryExecutableAndArguments(t *testing.T) {
	if err := validateNftInvocation("sh", []string{"-c", "anything"}, ""); err == nil {
		t.Fatal("arbitrary executable was accepted")
	}
	if err := validateNftInvocation("nft", []string{"list", "table\nadd table attacker"}, ""); err == nil {
		t.Fatal("newline-injected argument was accepted")
	}
	if err := validateNftInvocation("nft", []string{"-f", "-"}, strings.Repeat("x", maxNftScriptBytes+1)); err == nil {
		t.Fatal("oversized generated ruleset was accepted")
	}
	if err := validateNftInvocation("nft", []string{"-f", "-"}, "table inet fixed {}"); err != nil {
		t.Fatalf("fixed generated ruleset was rejected: %v", err)
	}
}

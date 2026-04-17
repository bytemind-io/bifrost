package handlers

import (
	"testing"

	"github.com/maximhq/bifrost/framework/configstore/tables"
)

func TestFindRedactedVirtualKey_DeletedFallback(t *testing.T) {
	result := findRedactedVirtualKey(nil, "vk-deleted", "Deleted Key")
	if result == nil {
		t.Fatalf("expected non-nil fallback virtual key")
	}
	if result.ID != "vk-deleted" {
		t.Fatalf("unexpected fallback id: %q", result.ID)
	}
	if result.Name != "Deleted Key (deleted)" {
		t.Fatalf("unexpected fallback name: %q", result.Name)
	}
}

func TestFindRedactedVirtualKey_UsesExistingRedactedKey(t *testing.T) {
	redacted := []tables.TableVirtualKey{
		{ID: "vk-1", Name: "Active Key"},
	}

	result := findRedactedVirtualKey(redacted, "vk-1", "Original Name")
	if result == nil {
		t.Fatalf("expected non-nil redacted virtual key")
	}
	if result.ID != "vk-1" {
		t.Fatalf("unexpected id: %q", result.ID)
	}
	if result.Name != "Active Key" {
		t.Fatalf("expected existing redacted key name to win, got %q", result.Name)
	}
}

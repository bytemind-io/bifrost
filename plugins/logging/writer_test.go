package logging

import (
	"testing"

	"github.com/maximhq/bifrost/framework/logstore"
)

func TestApplyModelAlias(t *testing.T) {
	t.Run("alias mapping applied surfaces alias as Model", func(t *testing.T) {
		entry := &logstore.Log{}
		applyModelAlias(entry, "gpt-4-mini", "gpt-4o-mini")
		if entry.Model != "gpt-4-mini" {
			t.Errorf("Model = %q, want alias %q", entry.Model, "gpt-4-mini")
		}
		if entry.Alias == nil || *entry.Alias != "gpt-4o-mini" {
			got := "<nil>"
			if entry.Alias != nil {
				got = *entry.Alias
			}
			t.Errorf("Alias = %q, want resolved %q", got, "gpt-4o-mini")
		}
	})

	t.Run("no alias mapping leaves Alias nil", func(t *testing.T) {
		entry := &logstore.Log{}
		applyModelAlias(entry, "gpt-4o", "gpt-4o")
		if entry.Model != "gpt-4o" {
			t.Errorf("Model = %q, want %q", entry.Model, "gpt-4o")
		}
		if entry.Alias != nil {
			t.Errorf("Alias = %q, want nil", *entry.Alias)
		}
	})

	t.Run("empty resolved falls back to requested", func(t *testing.T) {
		entry := &logstore.Log{}
		applyModelAlias(entry, "gpt-4o", "")
		if entry.Model != "gpt-4o" {
			t.Errorf("Model = %q, want %q", entry.Model, "gpt-4o")
		}
		if entry.Alias != nil {
			t.Errorf("Alias = %q, want nil", *entry.Alias)
		}
	})
}

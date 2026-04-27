package schemas

import "testing"

func TestPopulateExtraFields_AliasOverridesModel(t *testing.T) {
	t.Run("ChatResponse: alias overrides Model", func(t *testing.T) {
		r := &BifrostResponse{
			ChatResponse: &BifrostChatResponse{Model: "gpt-4o-mini"},
		}
		r.PopulateExtraFields(ChatCompletionRequest, OpenAI, "gpt-4-mini", "gpt-4o-mini")

		if r.ChatResponse.Model != "gpt-4-mini" {
			t.Errorf("Model = %q, want alias %q", r.ChatResponse.Model, "gpt-4-mini")
		}
		if r.ChatResponse.ExtraFields.OriginalModelRequested != "gpt-4-mini" {
			t.Errorf("OriginalModelRequested = %q, want %q", r.ChatResponse.ExtraFields.OriginalModelRequested, "gpt-4-mini")
		}
		if r.ChatResponse.ExtraFields.ResolvedModelUsed != "gpt-4o-mini" {
			t.Errorf("ResolvedModelUsed = %q, want %q", r.ChatResponse.ExtraFields.ResolvedModelUsed, "gpt-4o-mini")
		}
	})

	t.Run("ChatResponse: no alias keeps original model", func(t *testing.T) {
		r := &BifrostResponse{
			ChatResponse: &BifrostChatResponse{Model: "gpt-4o"},
		}
		r.PopulateExtraFields(ChatCompletionRequest, OpenAI, "gpt-4o", "gpt-4o")
		if r.ChatResponse.Model != "gpt-4o" {
			t.Errorf("Model = %q, want %q", r.ChatResponse.Model, "gpt-4o")
		}
	})

	t.Run("EmbeddingResponse: alias overrides Model", func(t *testing.T) {
		r := &BifrostResponse{
			EmbeddingResponse: &BifrostEmbeddingResponse{Model: "text-embedding-3-small"},
		}
		r.PopulateExtraFields(EmbeddingRequest, OpenAI, "embed-small", "text-embedding-3-small")
		if r.EmbeddingResponse.Model != "embed-small" {
			t.Errorf("Model = %q, want alias %q", r.EmbeddingResponse.Model, "embed-small")
		}
	})

	t.Run("nil response is safe", func(t *testing.T) {
		var r *BifrostResponse
		r.PopulateExtraFields(ChatCompletionRequest, OpenAI, "alias", "real")
	})

	t.Run("empty original keeps original Model", func(t *testing.T) {
		r := &BifrostResponse{
			ChatResponse: &BifrostChatResponse{Model: "gpt-4o-mini"},
		}
		r.PopulateExtraFields(ChatCompletionRequest, OpenAI, "", "gpt-4o-mini")
		if r.ChatResponse.Model != "gpt-4o-mini" {
			t.Errorf("Model = %q, want unchanged %q", r.ChatResponse.Model, "gpt-4o-mini")
		}
	})
}

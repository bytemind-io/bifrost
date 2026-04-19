package configstore

import (
	"context"
	"testing"

	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeleteVirtualKey_SharedBudgetAndRateLimit verifies DeleteVirtualKey behaves
// correctly when two provider configs reference the same Budget and RateLimit row.
// The cascade cleanup loop will issue a DELETE for the same id twice; the second
// must be a no-op rather than an error, otherwise the whole transaction rolls back
// and the VK is never tombstoned.
func TestDeleteVirtualKey_SharedBudgetAndRateLimit(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	sharedBudget := &tables.TableBudget{
		ID:            "budget-shared",
		MaxLimit:      10.0,
		ResetDuration: "1h",
	}
	require.NoError(t, store.CreateBudget(ctx, sharedBudget))

	tokenMax := int64(1000)
	tokenDur := "1h"
	sharedRateLimit := &tables.TableRateLimit{
		ID:                 "ratelimit-shared",
		TokenMaxLimit:      &tokenMax,
		TokenResetDuration: &tokenDur,
	}
	require.NoError(t, store.CreateRateLimit(ctx, sharedRateLimit))

	vk := &tables.TableVirtualKey{
		ID:       "vk-shared",
		Name:     "Shared VK",
		Value:    "vk-shared-value",
		IsActive: true,
	}
	require.NoError(t, store.CreateVirtualKey(ctx, vk))

	vkBudget := &tables.TableBudget{
		ID:            "vk-shared-budget",
		MaxLimit:      20.0,
		ResetDuration: "1h",
		VirtualKeyID:  &vk.ID,
	}
	require.NoError(t, store.CreateBudget(ctx, vkBudget))

	weight := 1.0
	rateLimitID := sharedRateLimit.ID
	for _, provider := range []string{"openai", "anthropic"} {
		pc := &tables.TableVirtualKeyProviderConfig{
			VirtualKeyID: vk.ID,
			Provider:     provider,
			Weight:       &weight,
			RateLimitID:  &rateLimitID,
		}
		require.NoError(t, store.CreateVirtualKeyProviderConfig(ctx, pc))
		budget := &tables.TableBudget{
			ID:               "budget-" + provider,
			MaxLimit:         10.0,
			ResetDuration:    "1h",
			ProviderConfigID: &pc.ID,
		}
		require.NoError(t, store.CreateBudget(ctx, budget))
	}

	configs, err := store.GetVirtualKeyProviderConfigs(ctx, vk.ID)
	require.NoError(t, err)
	require.Len(t, configs, 2, "expected two provider configs before delete")

	// The key assertion: delete must not error on the duplicate cleanup attempt.
	require.NoError(t, store.DeleteVirtualKey(ctx, vk.ID))

	// Provider configs gone.
	var pcCount int64
	require.NoError(t, store.db.WithContext(ctx).Model(&tables.TableVirtualKeyProviderConfig{}).
		Where("virtual_key_id = ?", vk.ID).Count(&pcCount).Error)
	assert.Equal(t, int64(0), pcCount, "provider configs must be hard-deleted")

	// VK-owned budget is removed.
	var budgetCount int64
	require.NoError(t, store.db.WithContext(ctx).Model(&tables.TableBudget{}).
		Where("id = ?", vkBudget.ID).Count(&budgetCount).Error)
	assert.Equal(t, int64(0), budgetCount, "vk budget must be cleaned up")

	// Shared provider-config rate limit is removed even when referenced twice.
	var rateLimitCount int64
	require.NoError(t, store.db.WithContext(ctx).Model(&tables.TableRateLimit{}).
		Where("id = ?", sharedRateLimit.ID).Count(&rateLimitCount).Error)
	assert.Equal(t, int64(0), rateLimitCount, "shared rate limit must be cleaned up")

	// VK itself is tombstoned (soft-deleted) so the same name/value can be reused.
	var raw tables.TableVirtualKey
	require.NoError(t, store.db.WithContext(ctx).Unscoped().First(&raw, "id = ?", vk.ID).Error)
	assert.True(t, raw.DeletedAt.Valid, "VK should be soft-deleted")
	assert.False(t, raw.IsActive)
	assert.NotEqual(t, "vk-shared-value", raw.Value, "value should be tombstoned")

	// Tombstone must NOT still reference the deleted rate limit, and all budgets must be gone.
	assert.Nil(t, raw.RateLimitID, "tombstone should drop rate_limit_id reference")
	require.NoError(t, store.db.WithContext(ctx).Model(&tables.TableBudget{}).
		Where("virtual_key_id = ?", vk.ID).Count(&budgetCount).Error)
	assert.Equal(t, int64(0), budgetCount, "tombstone should not keep virtual-key budgets")
}

// TestDeleteVirtualKey_FullCascade exercises the full cascade path at once:
// VK with its own Budget / RateLimit, two provider configs (with keys), and an
// MCP config. After delete, everything except the tombstoned VK row must be gone.
func TestDeleteVirtualKey_FullCascade(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	vkBudget := &tables.TableBudget{ID: "vk-budget", MaxLimit: 5.0, ResetDuration: "1h"}
	require.NoError(t, store.CreateBudget(ctx, vkBudget))
	tokenMax := int64(100)
	tokenDur := "1h"
	vkRateLimit := &tables.TableRateLimit{ID: "vk-ratelimit", TokenMaxLimit: &tokenMax, TokenResetDuration: &tokenDur}
	require.NoError(t, store.CreateRateLimit(ctx, vkRateLimit))

	pc1Budget := &tables.TableBudget{ID: "pc1-budget", MaxLimit: 1.0, ResetDuration: "1h"}
	require.NoError(t, store.CreateBudget(ctx, pc1Budget))
	pc1RateLimit := &tables.TableRateLimit{ID: "pc1-ratelimit", TokenMaxLimit: &tokenMax, TokenResetDuration: &tokenDur}
	require.NoError(t, store.CreateRateLimit(ctx, pc1RateLimit))

	pc2Budget := &tables.TableBudget{ID: "pc2-budget", MaxLimit: 2.0, ResetDuration: "1h"}
	require.NoError(t, store.CreateBudget(ctx, pc2Budget))
	pc2RateLimit := &tables.TableRateLimit{ID: "pc2-ratelimit", TokenMaxLimit: &tokenMax, TokenResetDuration: &tokenDur}
	require.NoError(t, store.CreateRateLimit(ctx, pc2RateLimit))

	vk := &tables.TableVirtualKey{
		ID:          "vk-cascade",
		Name:        "Cascade VK",
		Value:       "vk-cascade-value",
		IsActive:    true,
		RateLimitID: &vkRateLimit.ID,
	}
	require.NoError(t, store.CreateVirtualKey(ctx, vk))
	vkBudget.VirtualKeyID = &vk.ID
	require.NoError(t, store.UpdateBudget(ctx, vkBudget))

	weight := 1.0
	pc1RateLimitID := pc1RateLimit.ID
	pc1 := &tables.TableVirtualKeyProviderConfig{
		VirtualKeyID: vk.ID, Provider: "openai", Weight: &weight,
		RateLimitID: &pc1RateLimitID,
	}
	require.NoError(t, store.CreateVirtualKeyProviderConfig(ctx, pc1))
	pc1Budget.ProviderConfigID = &pc1.ID
	require.NoError(t, store.UpdateBudget(ctx, pc1Budget))

	pc2RateLimitID := pc2RateLimit.ID
	pc2 := &tables.TableVirtualKeyProviderConfig{
		VirtualKeyID: vk.ID, Provider: "anthropic", Weight: &weight,
		RateLimitID: &pc2RateLimitID,
	}
	require.NoError(t, store.CreateVirtualKeyProviderConfig(ctx, pc2))
	pc2Budget.ProviderConfigID = &pc2.ID
	require.NoError(t, store.UpdateBudget(ctx, pc2Budget))

	mcpClient := &tables.TableMCPClient{Name: "mcp-client-x", ConnectionType: "stdio"}
	require.NoError(t, store.db.WithContext(ctx).Create(mcpClient).Error)
	mcpCfg := &tables.TableVirtualKeyMCPConfig{
		VirtualKeyID: vk.ID,
		MCPClientID:  mcpClient.ID,
	}
	require.NoError(t, store.db.WithContext(ctx).Create(mcpCfg).Error)

	require.NoError(t, store.DeleteVirtualKey(ctx, vk.ID))

	// Assert: all dependent rows are hard-deleted.
	checks := []struct {
		name  string
		query func() int64
	}{
		{"provider configs", func() int64 {
			var c int64
			store.db.WithContext(ctx).Model(&tables.TableVirtualKeyProviderConfig{}).Where("virtual_key_id = ?", vk.ID).Count(&c)
			return c
		}},
		{"mcp configs", func() int64 {
			var c int64
			store.db.WithContext(ctx).Model(&tables.TableVirtualKeyMCPConfig{}).Where("virtual_key_id = ?", vk.ID).Count(&c)
			return c
		}},
		{"vk budget", func() int64 {
			var c int64
			store.db.WithContext(ctx).Model(&tables.TableBudget{}).Where("id = ?", vkBudget.ID).Count(&c)
			return c
		}},
		{"vk rate limit", func() int64 {
			var c int64
			store.db.WithContext(ctx).Model(&tables.TableRateLimit{}).Where("id = ?", vkRateLimit.ID).Count(&c)
			return c
		}},
		{"pc1 budget", func() int64 {
			var c int64
			store.db.WithContext(ctx).Model(&tables.TableBudget{}).Where("id = ?", pc1Budget.ID).Count(&c)
			return c
		}},
		{"pc1 rate limit", func() int64 {
			var c int64
			store.db.WithContext(ctx).Model(&tables.TableRateLimit{}).Where("id = ?", pc1RateLimit.ID).Count(&c)
			return c
		}},
		{"pc2 budget", func() int64 {
			var c int64
			store.db.WithContext(ctx).Model(&tables.TableBudget{}).Where("id = ?", pc2Budget.ID).Count(&c)
			return c
		}},
		{"pc2 rate limit", func() int64 {
			var c int64
			store.db.WithContext(ctx).Model(&tables.TableRateLimit{}).Where("id = ?", pc2RateLimit.ID).Count(&c)
			return c
		}},
	}
	for _, c := range checks {
		assert.Equal(t, int64(0), c.query(), "%s should be hard-deleted", c.name)
	}

	// VK itself should be tombstoned (present in unscoped query, absent from scoped).
	var raw tables.TableVirtualKey
	require.NoError(t, store.db.WithContext(ctx).Unscoped().First(&raw, "id = ?", vk.ID).Error)
	assert.True(t, raw.DeletedAt.Valid)
	assert.Nil(t, raw.RateLimitID)
}

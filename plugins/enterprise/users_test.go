package enterprise

import (
	"context"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	return db
}

func TestUserStore_CreateAndGet(t *testing.T) {
	db := setupTestDB(t)
	store, err := NewUserStore(db)
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}
	ctx := context.Background()

	user, err := store.CreateUser(ctx, "test@example.com", "Test User", "password123", RoleUser, nil)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if user.ID == "" {
		t.Error("user ID should not be empty")
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", user.Email)
	}
	if user.Role != string(RoleUser) {
		t.Errorf("expected role user, got %s", user.Role)
	}

	// Get by ID
	found, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if found.Email != user.Email {
		t.Errorf("email mismatch: %s vs %s", found.Email, user.Email)
	}

	// Get by email
	found2, err := store.GetUserByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("failed to get user by email: %v", err)
	}
	if found2.ID != user.ID {
		t.Error("user IDs should match")
	}
}

func TestUserStore_ValidatePassword(t *testing.T) {
	db := setupTestDB(t)
	store, err := NewUserStore(db)
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "test@example.com", "Test", "mypassword", RoleUser, nil)

	if !store.ValidatePassword(user, "mypassword") {
		t.Error("correct password should validate")
	}
	if store.ValidatePassword(user, "wrongpassword") {
		t.Error("wrong password should not validate")
	}
}

func TestUserStore_ListUsers(t *testing.T) {
	db := setupTestDB(t)
	store, err := NewUserStore(db)
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}
	ctx := context.Background()

	store.CreateUser(ctx, "alice@example.com", "Alice", "pass", RoleAdmin, nil)
	teamID := "team-1"
	store.CreateUser(ctx, "bob@example.com", "Bob", "pass", RoleUser, &teamID)
	store.CreateUser(ctx, "charlie@example.com", "Charlie", "pass", RoleUser, &teamID)

	// List all
	users, total, err := store.ListUsers(ctx, nil, "", 0, 10)
	if err != nil {
		t.Fatalf("failed to list users: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 users, got %d", total)
	}
	if len(users) != 3 {
		t.Errorf("expected 3 users in result, got %d", len(users))
	}

	// List by team
	users, total, err = store.ListUsers(ctx, &teamID, "", 0, 10)
	if err != nil {
		t.Fatalf("failed to list users by team: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 users in team, got %d", total)
	}

	// Search
	users, total, err = store.ListUsers(ctx, nil, "alice", 0, 10)
	if err != nil {
		t.Fatalf("failed to search users: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 user matching 'alice', got %d", total)
	}
}

func TestUserStore_UpdateUser(t *testing.T) {
	db := setupTestDB(t)
	store, err := NewUserStore(db)
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "test@example.com", "Test", "pass", RoleUser, nil)

	updated, err := store.UpdateUser(ctx, user.ID, map[string]interface{}{
		"name": "Updated Name",
		"role": string(RoleTeamManager),
	})
	if err != nil {
		t.Fatalf("failed to update user: %v", err)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("name should be updated, got %s", updated.Name)
	}
	if updated.Role != string(RoleTeamManager) {
		t.Errorf("role should be updated, got %s", updated.Role)
	}
}

func TestUserStore_DeleteUser(t *testing.T) {
	db := setupTestDB(t)
	store, err := NewUserStore(db)
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "test@example.com", "Test", "pass", RoleUser, nil)
	err = store.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}

	_, err = store.GetUser(ctx, user.ID)
	if err == nil {
		t.Error("user should not be found after deletion")
	}
}

func TestUserStore_EnsureAdminExists(t *testing.T) {
	db := setupTestDB(t)
	store, err := NewUserStore(db)
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}
	ctx := context.Background()

	// First call should create admin
	err = store.EnsureAdminExists(ctx, "admin@test.com", "Admin", "admin123")
	if err != nil {
		t.Fatalf("failed to ensure admin: %v", err)
	}

	// Second call should be a no-op
	err = store.EnsureAdminExists(ctx, "admin2@test.com", "Admin2", "admin456")
	if err != nil {
		t.Fatalf("second ensure admin should not fail: %v", err)
	}

	// Should still have only 1 admin
	users, total, _ := store.ListUsers(ctx, nil, "", 0, 10)
	if total != 1 {
		t.Errorf("expected 1 user, got %d", total)
	}
	if users[0].Email != "admin@test.com" {
		t.Errorf("admin email should be admin@test.com, got %s", users[0].Email)
	}
}

func TestUserStore_SessionMapping(t *testing.T) {
	db := setupTestDB(t)
	store, err := NewUserStore(db)
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "test@example.com", "Test", "pass", RoleUser, nil)

	// Create session mapping
	tokenHash := "abc123hash"
	err = store.CreateUserSession(ctx, user.ID, tokenHash, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("failed to create user session: %v", err)
	}

	// Look up user by token hash
	found, err := store.GetUserByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("failed to get user by token hash: %v", err)
	}
	if found.ID != user.ID {
		t.Errorf("user ID mismatch: %s vs %s", found.ID, user.ID)
	}

	// Expired session should not return user
	err = store.CreateUserSession(ctx, user.ID, "expiredhash", time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("failed to create expired session: %v", err)
	}
	_, err = store.GetUserByTokenHash(ctx, "expiredhash")
	if err == nil {
		t.Error("expired session should not return a user")
	}
}

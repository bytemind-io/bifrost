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

	user, err := store.CreateUser(ctx, "test@example.com", "Test User", "password123", "Viewer", nil)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if user.ID == "" {
		t.Error("user ID should not be empty")
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", user.Email)
	}
	if user.Role != string("Viewer") {
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

	user, _ := store.CreateUser(ctx, "test@example.com", "Test", "mypassword", "Viewer", nil)

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

	store.CreateUser(ctx, "alice@example.com", "Alice", "pass", "Admin", nil)
	teamID := "team-1"
	store.CreateUser(ctx, "bob@example.com", "Bob", "pass", "Viewer", &teamID)
	store.CreateUser(ctx, "charlie@example.com", "Charlie", "pass", "Viewer", &teamID)

	// List all
	users, total, err := store.ListUsers(ctx, UserListParams{Limit: 10})
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
	users, total, err = store.ListUsers(ctx, UserListParams{TeamID: &teamID, Limit: 10})
	if err != nil {
		t.Fatalf("failed to list users by team: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 users in team, got %d", total)
	}

	// Search
	users, total, err = store.ListUsers(ctx, UserListParams{Search: "alice", Limit: 10})
	if err != nil {
		t.Fatalf("failed to search users: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 user matching 'alice', got %d", total)
	}

	// Filter by role
	users, total, err = store.ListUsers(ctx, UserListParams{Role: "Viewer", Limit: 10})
	if err != nil {
		t.Fatalf("failed to filter by role: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 users with role 'viewer', got %d", total)
	}

	// Filter by active status
	active := true
	users, total, err = store.ListUsers(ctx, UserListParams{IsActive: &active, Limit: 10})
	if err != nil {
		t.Fatalf("failed to filter by active: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 active users, got %d", total)
	}
}

func TestUserStore_UpdateUser(t *testing.T) {
	db := setupTestDB(t)
	store, err := NewUserStore(db)
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "test@example.com", "Test", "pass", "Viewer", nil)

	updated, err := store.UpdateUser(ctx, user.ID, map[string]interface{}{
		"name": "Updated Name",
		"role": string("Developer"),
	})
	if err != nil {
		t.Fatalf("failed to update user: %v", err)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("name should be updated, got %s", updated.Name)
	}
	if updated.Role != string("Developer") {
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

	user, _ := store.CreateUser(ctx, "test@example.com", "Test", "pass", "Viewer", nil)
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
	users, total, _ := store.ListUsers(ctx, UserListParams{Limit: 10})
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

	user, _ := store.CreateUser(ctx, "test@example.com", "Test", "pass", "Viewer", nil)

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

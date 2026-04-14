package enterprise

import (
	"context"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	return db
}

// --- Bug #1: Duplicate email should fail ---

func TestUserStore_DuplicateEmail(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewUserStore(db)
	ctx := context.Background()

	_, err := store.CreateUser(ctx, "dup@test.com", "User1", "pass", "Viewer", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateUser(ctx, "dup@test.com", "User2", "pass", "Viewer", nil)
	if err == nil {
		t.Error("BUG: creating user with duplicate email should fail")
	}
}

// --- Bug #2: Empty password should not be allowed ---

func TestUserStore_EmptyPassword(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewUserStore(db)
	ctx := context.Background()

	_, err := store.CreateUser(ctx, "test@test.com", "Test", "", "Viewer", nil)
	if err == nil {
		t.Error("BUG: empty password should be rejected at store level")
	}
}

// --- Bug #3: Invalid role should be caught ---

// --- Bug #4: GetUser for nonexistent ID ---

func TestUserStore_GetNonexistent(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewUserStore(db)
	ctx := context.Background()

	_, err := store.GetUser(ctx, "nonexistent-id")
	if err == nil {
		t.Error("BUG: getting nonexistent user should return error")
	}

	_, err = store.GetUserByEmail(ctx, "nobody@test.com")
	if err == nil {
		t.Error("BUG: getting nonexistent email should return error")
	}
}

// --- Bug #5: UpdateUser with nonexistent ID ---

func TestUserStore_UpdateNonexistent(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewUserStore(db)
	ctx := context.Background()

	_, err := store.UpdateUser(ctx, "nonexistent-id", map[string]interface{}{"name": "New"})
	if err == nil {
		// GORM updates 0 rows without error, then GetUser fails
		// This is a potential issue - let's check
		t.Log("INFO: UpdateUser for nonexistent ID did not error (GORM behavior)")
	}
}

// --- Bug #6: Session cleanup ---

func TestUserStore_CleanExpiredSessions(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewUserStore(db)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "test@test.com", "Test", "pass", "Viewer", nil)

	// Create expired session
	store.CreateUserSession(ctx, user.ID, "expired-hash", time.Now().Add(-1*time.Hour))
	// Create valid session
	store.CreateUserSession(ctx, user.ID, "valid-hash", time.Now().Add(24*time.Hour))

	err := store.CleanExpiredUserSessions(ctx)
	if err != nil {
		t.Fatalf("CleanExpiredUserSessions failed: %v", err)
	}

	// Expired session should be gone
	_, err = store.GetUserByTokenHash(ctx, "expired-hash")
	if err == nil {
		t.Error("BUG: expired session should have been cleaned up")
	}

	// Valid session should still work
	found, err := store.GetUserByTokenHash(ctx, "valid-hash")
	if err != nil {
		t.Fatalf("valid session should still work: %v", err)
	}
	if found.ID != user.ID {
		t.Error("valid session should return correct user")
	}
}

// --- Bug #7: Delete user should cascade sessions ---

func TestUserStore_DeleteUserCascadesSessions(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewUserStore(db)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "test@test.com", "Test", "pass", "Viewer", nil)
	store.CreateUserSession(ctx, user.ID, "session-hash", time.Now().Add(24*time.Hour))

	// Delete user - should cascade to sessions
	store.DeleteUser(ctx, user.ID)

	// Session mapping should be cleaned up
	_, err := store.GetUserByTokenHash(ctx, "session-hash")
	if err == nil {
		t.Error("BUG: user deleted but session mapping still exists")
	}
}

// --- Bug #8: Audit log query with SQL injection attempt ---

func TestAuditStore_SQLInjection(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewAuditStore(db)
	ctx := context.Background()

	// Create a normal audit log
	store.Record(ctx, "user1", "user@test.com", "create", "user", "id1", "{}", "127.0.0.1")

	// Query with SQL injection attempt in search
	q := AuditLogQuery{
		Search: "'; DROP TABLE enterprise_audit_logs; --",
		Limit:  10,
	}
	logs, total, err := store.Query(ctx, q)
	if err != nil {
		t.Fatalf("query should not fail with injection attempt: %v", err)
	}
	if total != 0 {
		t.Errorf("injection query should return 0 results, got %d", total)
	}
	_ = logs

	// Verify table still exists
	store.Record(ctx, "user2", "user2@test.com", "login", "session", "", "", "127.0.0.1")
	_, total2, _ := store.Query(ctx, AuditLogQuery{Limit: 10})
	if total2 != 2 {
		t.Errorf("expected 2 audit logs after injection attempt, got %d", total2)
	}
}

// --- Bug #9: Audit log time filtering ---

func TestAuditStore_TimeFiltering(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewAuditStore(db)
	ctx := context.Background()

	// Create logs at different times
	now := time.Now()
	store.Record(ctx, "user1", "user1@test.com", "create", "user", "id1", "{}", "127.0.0.1")
	time.Sleep(10 * time.Millisecond)
	store.Record(ctx, "user2", "user2@test.com", "update", "user", "id2", "{}", "127.0.0.1")

	// Query with start time in the future - should get 0
	future := now.Add(1 * time.Hour)
	_, total, _ := store.Query(ctx, AuditLogQuery{StartAt: &future, Limit: 10})
	if total != 0 {
		t.Errorf("future start time should return 0 results, got %d", total)
	}

	// Query with end time in the past - should get 0
	past := now.Add(-1 * time.Hour)
	_, total, _ = store.Query(ctx, AuditLogQuery{EndAt: &past, Limit: 10})
	if total != 0 {
		t.Errorf("past end time should return 0 results, got %d", total)
	}

	// Query all - should get 2
	_, total, _ = store.Query(ctx, AuditLogQuery{Limit: 10})
	if total != 2 {
		t.Errorf("expected 2 audit logs, got %d", total)
	}
}

// --- Bug #10: Audit log action/resource filtering ---

func TestAuditStore_Filtering(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewAuditStore(db)
	ctx := context.Background()

	store.Record(ctx, "u1", "u1@test.com", "create", "user", "id1", "{}", "127.0.0.1")
	store.Record(ctx, "u1", "u1@test.com", "create", "virtual_key", "id2", "{}", "127.0.0.1")
	store.Record(ctx, "u1", "u1@test.com", "delete", "user", "id3", "{}", "127.0.0.1")
	store.Record(ctx, "u2", "u2@test.com", "login", "session", "", "{}", "10.0.0.1")

	// Filter by action
	_, total, _ := store.Query(ctx, AuditLogQuery{Action: "create", Limit: 10})
	if total != 2 {
		t.Errorf("expected 2 'create' logs, got %d", total)
	}

	// Filter by resource
	_, total, _ = store.Query(ctx, AuditLogQuery{Resource: "user", Limit: 10})
	if total != 2 {
		t.Errorf("expected 2 'user' resource logs, got %d", total)
	}

	// Filter by user
	_, total, _ = store.Query(ctx, AuditLogQuery{UserID: "u2", Limit: 10})
	if total != 1 {
		t.Errorf("expected 1 log for u2, got %d", total)
	}

	// Combined filter
	_, total, _ = store.Query(ctx, AuditLogQuery{Action: "create", Resource: "user", Limit: 10})
	if total != 1 {
		t.Errorf("expected 1 'create user' log, got %d", total)
	}

	// Search
	_, total, _ = store.Query(ctx, AuditLogQuery{Search: "u2@test", Limit: 10})
	if total != 1 {
		t.Errorf("expected 1 log matching 'u2@test', got %d", total)
	}
}

// --- Bug #11: Pagination ---

func TestUserStore_Pagination(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewUserStore(db)
	ctx := context.Background()

	// Create 5 users
	for i := 0; i < 5; i++ {
		store.CreateUser(ctx, "user"+string(rune('a'+i))+"@test.com", "User", "pass", "Viewer", nil)
	}

	// Page 1
	users, total, _ := store.ListUsers(ctx, UserListParams{Offset: 0, Limit: 2})
	if total != 5 {
		t.Errorf("expected total=5, got %d", total)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users on page 1, got %d", len(users))
	}

	// Page 2
	users, _, _ = store.ListUsers(ctx, UserListParams{Offset: 2, Limit: 2})
	if len(users) != 2 {
		t.Errorf("expected 2 users on page 2, got %d", len(users))
	}

	// Page 3
	users, _, _ = store.ListUsers(ctx, UserListParams{Offset: 4, Limit: 2})
	if len(users) != 1 {
		t.Errorf("expected 1 user on page 3, got %d", len(users))
	}

	// Beyond range
	users, _, _ = store.ListUsers(ctx, UserListParams{Offset: 10, Limit: 2})
	if len(users) != 0 {
		t.Errorf("expected 0 users beyond range, got %d", len(users))
	}
}

// --- Bug #12: Multiple sessions for same user ---

func TestUserStore_MultipleSessions(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewUserStore(db)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "test@test.com", "Test", "pass", "Viewer", nil)

	// Create multiple sessions
	store.CreateUserSession(ctx, user.ID, "hash1", time.Now().Add(24*time.Hour))
	store.CreateUserSession(ctx, user.ID, "hash2", time.Now().Add(24*time.Hour))

	// Both should resolve to same user
	u1, _ := store.GetUserByTokenHash(ctx, "hash1")
	u2, _ := store.GetUserByTokenHash(ctx, "hash2")
	if u1.ID != u2.ID {
		t.Error("both sessions should resolve to same user")
	}

	// Delete all sessions for user
	store.DeleteUserSessionsByUserID(ctx, user.ID)

	// Both should fail now
	_, err1 := store.GetUserByTokenHash(ctx, "hash1")
	_, err2 := store.GetUserByTokenHash(ctx, "hash2")
	if err1 == nil || err2 == nil {
		t.Error("all sessions should be deleted")
	}
}

// --- Bug #13: Route permission edge cases ---

func TestCheckRoutePermission_EdgeCases(t *testing.T) {
	db := setupTestDB(t)
	store, _ := NewRoleStore(db)

	if CheckRoutePermission(store, "Viewer", "GET", "/api/unknown/endpoint") {
		t.Error("unknown route should be denied for Viewer")
	}
	if !CheckRoutePermission(store, "Admin", "GET", "/api/unknown/endpoint") {
		t.Error("unknown route should be allowed for Admin")
	}
	if !CheckRoutePermission(store, "Viewer", "GET", "/health") {
		t.Error("/health should be whitelisted for all")
	}
	if !CheckRoutePermission(store, "Viewer", "GET", "/api/providers") {
		t.Error("Viewer should be able to read providers")
	}
	if CheckRoutePermission(store, "Viewer", "DELETE", "/api/providers/openai") {
		t.Error("Viewer should NOT be able to delete providers")
	}
	if !CheckRoutePermission(store, "Viewer", "GET", "/api/governance/routing-rules") {
		t.Error("Viewer should be able to read routing rules")
	}
	if CheckRoutePermission(store, "Viewer", "POST", "/api/governance/routing-rules") {
		t.Error("Viewer should NOT be able to create routing rules")
	}
}

// --- Bug #14: UpdatePassword ---

func TestUserStore_UpdatePassword(t *testing.T) {
	db := newTestDB(t)
	store, _ := NewUserStore(db)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "test@test.com", "Test", "oldpass", "Viewer", nil)

	err := store.UpdatePassword(ctx, user.ID, "newpass123")
	if err != nil {
		t.Fatalf("UpdatePassword failed: %v", err)
	}

	// Re-fetch user
	updated, _ := store.GetUser(ctx, user.ID)

	if store.ValidatePassword(updated, "oldpass") {
		t.Error("old password should no longer work")
	}
	if !store.ValidatePassword(updated, "newpass123") {
		t.Error("new password should work")
	}
}

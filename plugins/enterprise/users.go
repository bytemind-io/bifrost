package enterprise

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// TableUser represents a user in the enterprise system.
type TableUser struct {
	ID        string         `gorm:"primaryKey;type:varchar(255)" json:"id"`
	Email     string         `gorm:"uniqueIndex;type:varchar(255);not null" json:"email"`
	Name      string         `gorm:"type:varchar(255);not null" json:"name"`
	Password  string         `gorm:"type:text;not null" json:"-"`
	Role      string         `gorm:"type:varchar(50);not null;default:'user'" json:"role"`
	TeamID    *string        `gorm:"type:varchar(255);index" json:"team_id,omitempty"`
	IsActive  bool           `gorm:"default:true" json:"is_active"`
	CreatedAt time.Time      `gorm:"," json:"created_at"`
	UpdatedAt time.Time      `gorm:"," json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

// TableName sets the table name.
func (TableUser) TableName() string { return "enterprise_users" }

// UserStore provides CRUD operations for users.
type UserStore struct {
	db *gorm.DB
}

// NewUserStore creates a new user store and runs migrations.
func NewUserStore(db *gorm.DB) (*UserStore, error) {
	if err := db.AutoMigrate(&TableUser{}, &TableUserSession{}); err != nil {
		return nil, fmt.Errorf("failed to migrate enterprise tables: %w", err)
	}
	return &UserStore{db: db}, nil
}

// CreateUser creates a new user with hashed password.
// role is validated by the handler against the RoleStore.
func (s *UserStore) CreateUser(ctx context.Context, email, name, password, role string, teamID *string) (*TableUser, error) {
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if role == "" {
		return nil, fmt.Errorf("role cannot be empty")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &TableUser{
		ID:        uuid.New().String(),
		Email:     email,
		Name:      name,
		Password:  string(hashedPassword),
		Role:      role,
		TeamID:    teamID,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	return user, nil
}

// GetUser retrieves a user by ID.
func (s *UserStore) GetUser(ctx context.Context, id string) (*TableUser, error) {
	var user TableUser
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email.
func (s *UserStore) GetUserByEmail(ctx context.Context, email string) (*TableUser, error) {
	var user TableUser
	if err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// UserListParams defines query parameters for listing users.
type UserListParams struct {
	TeamID   *string
	Role     string
	IsActive *bool
	Search   string
	Offset   int
	Limit    int
}

// ListUsers returns paginated user list with optional filters.
func (s *UserStore) ListUsers(ctx context.Context, params UserListParams) ([]TableUser, int64, error) {
	var users []TableUser
	var total int64

	query := s.db.WithContext(ctx).Model(&TableUser{})
	if params.TeamID != nil {
		query = query.Where("team_id = ?", *params.TeamID)
	}
	if params.Role != "" {
		query = query.Where("role = ?", params.Role)
	}
	if params.IsActive != nil {
		query = query.Where("is_active = ?", *params.IsActive)
	}
	if params.Search != "" {
		query = query.Where("name LIKE ? OR email LIKE ?", "%"+params.Search+"%", "%"+params.Search+"%")
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if params.Limit == 0 {
		params.Limit = 20
	}
	if err := query.Order("created_at DESC").Offset(params.Offset).Limit(params.Limit).Find(&users).Error; err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

// UserStats returns aggregate user statistics.
type UserStats struct {
	Total          int64            `json:"total"`
	Active         int64            `json:"active"`
	Inactive       int64            `json:"inactive"`
	ByRole         map[string]int64 `json:"by_role"`
	ActiveSessions int64            `json:"active_sessions"`
}

// GetUserStats returns user statistics.
func (s *UserStore) GetUserStats(ctx context.Context) (*UserStats, error) {
	stats := &UserStats{ByRole: make(map[string]int64)}

	s.db.WithContext(ctx).Model(&TableUser{}).Count(&stats.Total)
	s.db.WithContext(ctx).Model(&TableUser{}).Where("is_active = ?", true).Count(&stats.Active)
	stats.Inactive = stats.Total - stats.Active

	type roleCount struct {
		Role  string
		Count int64
	}
	var roles []roleCount
	s.db.WithContext(ctx).Model(&TableUser{}).Select("role, count(*) as count").Group("role").Scan(&roles)
	for _, r := range roles {
		stats.ByRole[r.Role] = r.Count
	}

	s.db.WithContext(ctx).Model(&TableUserSession{}).Where("expires_at > ?", time.Now()).Count(&stats.ActiveSessions)
	return stats, nil
}

// UpdateUser updates user fields.
func (s *UserStore) UpdateUser(ctx context.Context, id string, updates map[string]interface{}) (*TableUser, error) {
	updates["updated_at"] = time.Now()
	if err := s.db.WithContext(ctx).Model(&TableUser{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

// UpdatePassword updates user password.
func (s *UserStore) UpdatePassword(ctx context.Context, id, newPassword string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Model(&TableUser{}).Where("id = ?", id).Updates(map[string]interface{}{
		"password":   string(hashed),
		"updated_at": time.Now(),
	}).Error
}

// DeleteUser deletes a user and cleans up their sessions.
func (s *UserStore) DeleteUser(ctx context.Context, id string) error {
	// Clean up session mappings first
	if err := s.DeleteUserSessionsByUserID(ctx, id); err != nil {
		return err
	}
	return s.db.WithContext(ctx).Where("id = ?", id).Delete(&TableUser{}).Error
}

// ValidatePassword checks if the provided password matches the stored hash.
func (s *UserStore) ValidatePassword(user *TableUser, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	return err == nil
}

// EnsureAdminExists creates a default admin user if no admin exists.
func (s *UserStore) EnsureAdminExists(ctx context.Context, email, name, password string) error {
	var count int64
	s.db.WithContext(ctx).Model(&TableUser{}).Where("role = ?", "Admin").Count(&count)
	if count > 0 {
		return nil
	}
	_, err := s.CreateUser(ctx, email, name, password, "Admin", nil)
	return err
}

// --- Session-User Mapping ---

// TableUserSession maps session tokens to enterprise users.
type TableUserSession struct {
	ID        string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID    string    `gorm:"type:varchar(255);index;not null" json:"user_id"`
	TokenHash string    `gorm:"type:varchar(64);uniqueIndex;not null" json:"-"`
	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
	ExpiresAt time.Time `gorm:"index;not null" json:"expires_at"`
}

func (TableUserSession) TableName() string { return "enterprise_user_sessions" }

// MigrateSessionTable runs the migration for the user-session mapping table.
func (s *UserStore) MigrateSessionTable() error {
	return s.db.AutoMigrate(&TableUserSession{})
}

// CreateUserSession creates a mapping between a session token and a user.
func (s *UserStore) CreateUserSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	session := &TableUserSession{
		ID:        uuid.New().String(),
		UserID:    userID,
		TokenHash: tokenHash,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
	return s.db.WithContext(ctx).Create(session).Error
}

// GetUserByTokenHash finds the enterprise user associated with a session token hash.
func (s *UserStore) GetUserByTokenHash(ctx context.Context, tokenHash string) (*TableUser, error) {
	var mapping TableUserSession
	if err := s.db.WithContext(ctx).Where("token_hash = ? AND expires_at > ?", tokenHash, time.Now()).First(&mapping).Error; err != nil {
		return nil, err
	}
	return s.GetUser(ctx, mapping.UserID)
}

// DeleteUserSessionsByUserID removes all sessions for a user.
func (s *UserStore) DeleteUserSessionsByUserID(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&TableUserSession{}).Error
}

// ListUsersByTeam returns all users belonging to a specific team.
func (s *UserStore) ListUsersByTeam(ctx context.Context, teamID string) ([]TableUser, error) {
	var users []TableUser
	if err := s.db.WithContext(ctx).Where("team_id = ?", teamID).Order("created_at DESC").Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

// AssignUserToTeam sets a user's team_id.
func (s *UserStore) AssignUserToTeam(ctx context.Context, userID string, teamID string) error {
	return s.db.WithContext(ctx).Model(&TableUser{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"team_id":    teamID,
		"updated_at": time.Now(),
	}).Error
}

// RemoveUserFromTeam clears a user's team_id.
func (s *UserStore) RemoveUserFromTeam(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).Model(&TableUser{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"team_id":    nil,
		"updated_at": time.Now(),
	}).Error
}

// CountUsersByRole returns the count of users grouped by role.
func (s *UserStore) CountUsersByRole(ctx context.Context) (map[string]int64, error) {
	type result struct {
		Role  string
		Count int64
	}
	var results []result
	if err := s.db.WithContext(ctx).Model(&TableUser{}).Select("role, count(*) as count").Group("role").Scan(&results).Error; err != nil {
		return nil, err
	}
	counts := make(map[string]int64)
	for _, r := range results {
		counts[r.Role] = r.Count
	}
	return counts, nil
}

// CountActiveSessions returns the number of non-expired sessions.
func (s *UserStore) CountActiveSessions(ctx context.Context) (int64, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&TableUserSession{}).Where("expires_at > ?", time.Now()).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// DeleteUserSessionByTokenHash removes a specific session by its token hash.
func (s *UserStore) DeleteUserSessionByTokenHash(ctx context.Context, tokenHash string) error {
	return s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).Delete(&TableUserSession{}).Error
}

// CleanExpiredUserSessions removes expired session mappings.
func (s *UserStore) CleanExpiredUserSessions(ctx context.Context) error {
	return s.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&TableUserSession{}).Error
}

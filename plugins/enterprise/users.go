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

// ValidRoles is the set of valid role values.
var ValidRoles = map[Role]bool{
	RoleAdmin:       true,
	RoleTeamManager: true,
	RoleUser:        true,
	RoleViewer:      true,
}

// CreateUser creates a new user with hashed password.
func (s *UserStore) CreateUser(ctx context.Context, email, name, password string, role Role, teamID *string) (*TableUser, error) {
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if !ValidRoles[role] {
		return nil, fmt.Errorf("invalid role: %s", role)
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
		Role:      string(role),
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

// ListUsers returns paginated user list, optionally filtered by team.
func (s *UserStore) ListUsers(ctx context.Context, teamID *string, search string, offset, limit int) ([]TableUser, int64, error) {
	var users []TableUser
	var total int64

	query := s.db.WithContext(ctx).Model(&TableUser{})
	if teamID != nil {
		query = query.Where("team_id = ?", *teamID)
	}
	if search != "" {
		query = query.Where("name LIKE ? OR email LIKE ?", "%"+search+"%", "%"+search+"%")
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := query.Order("created_at DESC").Offset(offset).Limit(limit).Find(&users).Error; err != nil {
		return nil, 0, err
	}
	return users, total, nil
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
	s.db.WithContext(ctx).Model(&TableUser{}).Where("role = ?", string(RoleAdmin)).Count(&count)
	if count > 0 {
		return nil
	}
	_, err := s.CreateUser(ctx, email, name, password, RoleAdmin, nil)
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

// CleanExpiredUserSessions removes expired session mappings.
func (s *UserStore) CleanExpiredUserSessions(ctx context.Context) error {
	return s.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&TableUserSession{}).Error
}

package enterprise

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TableAuditLog records all significant user actions.
type TableAuditLog struct {
	ID         string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
	UserID     string    `gorm:"type:varchar(255);index" json:"user_id"`
	UserEmail  string    `gorm:"type:varchar(255)" json:"user_email"`
	Action     string    `gorm:"type:varchar(50);index" json:"action"`
	Resource   string    `gorm:"type:varchar(100);index" json:"resource"`
	ResourceID string    `gorm:"type:varchar(255)" json:"resource_id"`
	Details    string    `gorm:"type:text" json:"details"`
	IP         string    `gorm:"type:varchar(100)" json:"ip"`
	CreatedAt  time.Time `gorm:"index;not null" json:"created_at"`
}

// TableName sets the table name.
func (TableAuditLog) TableName() string { return "enterprise_audit_logs" }

// AuditStore provides operations for audit logs.
type AuditStore struct {
	db *gorm.DB
}

// NewAuditStore creates a new audit store and runs migrations.
func NewAuditStore(db *gorm.DB) (*AuditStore, error) {
	if err := db.AutoMigrate(&TableAuditLog{}); err != nil {
		return nil, fmt.Errorf("failed to migrate audit logs table: %w", err)
	}
	return &AuditStore{db: db}, nil
}

// Record creates an audit log entry.
func (s *AuditStore) Record(ctx context.Context, userID, userEmail, action, resource, resourceID, details, ip string) error {
	log := &TableAuditLog{
		ID:         uuid.New().String(),
		UserID:     userID,
		UserEmail:  userEmail,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
		IP:         ip,
		CreatedAt:  time.Now(),
	}
	return s.db.WithContext(ctx).Create(log).Error
}

// AuditLogQuery defines query parameters for audit logs.
type AuditLogQuery struct {
	UserID   string
	Action   string
	Resource string
	StartAt  *time.Time
	EndAt    *time.Time
	Search   string
	Offset   int
	Limit    int
}

// Query retrieves audit logs with filtering.
func (s *AuditStore) Query(ctx context.Context, q AuditLogQuery) ([]TableAuditLog, int64, error) {
	var logs []TableAuditLog
	var total int64

	query := s.db.WithContext(ctx).Model(&TableAuditLog{})
	if q.UserID != "" {
		query = query.Where("user_id = ?", q.UserID)
	}
	if q.Action != "" {
		query = query.Where("action = ?", q.Action)
	}
	if q.Resource != "" {
		query = query.Where("resource = ?", q.Resource)
	}
	if q.StartAt != nil {
		query = query.Where("created_at >= ?", *q.StartAt)
	}
	if q.EndAt != nil {
		query = query.Where("created_at <= ?", *q.EndAt)
	}
	if q.Search != "" {
		query = query.Where("user_email LIKE ? OR details LIKE ?", "%"+q.Search+"%", "%"+q.Search+"%")
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if err := query.Order("created_at DESC").Offset(q.Offset).Limit(q.Limit).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

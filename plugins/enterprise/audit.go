package enterprise

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Event types
const (
	EventTypeAuthentication      = "authentication"
	EventTypeAuthorization       = "authorization"
	EventTypeConfigurationChange = "configuration_change"
	EventTypeDataAccess          = "data_access"
	EventTypeSecurityEvent       = "security_event"
)

// Severity levels
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Status values
const (
	StatusSuccess = "success"
	StatusFailed  = "failed"
	StatusBlocked = "blocked"
)

// TableAuditLog records all security-relevant events.
type TableAuditLog struct {
	ID         string    `gorm:"primaryKey;type:varchar(255)" json:"event_id"`
	EventType  string    `gorm:"type:varchar(50);index;not null" json:"event_type"`
	Action     string    `gorm:"type:varchar(100);index;not null" json:"action"`
	Status     string    `gorm:"type:varchar(20);index;default:'success'" json:"status"`
	Severity   string    `gorm:"type:varchar(20);index;default:'low'" json:"severity"`
	UserID     string    `gorm:"type:varchar(255);index" json:"user_id"`
	UserEmail  string    `gorm:"type:varchar(255)" json:"user_email"`
	IP         string    `gorm:"type:varchar(100)" json:"ip_address"`
	Resource   string    `gorm:"type:varchar(100);index" json:"resource"`
	ResourceID string    `gorm:"type:varchar(255)" json:"resource_id"`
	Details    string    `gorm:"type:text" json:"details"`
	CreatedAt  time.Time `gorm:"index;not null" json:"timestamp"`
}

func (TableAuditLog) TableName() string { return "enterprise_audit_logs" }

// AuditEvent represents an audit event to be recorded asynchronously.
type AuditEvent struct {
	EventType  string
	Action     string
	Status     string
	Severity   string
	UserID     string
	UserEmail  string
	IP         string
	Resource   string
	ResourceID string
	Details    string
}

// AuditStore provides event-driven audit logging.
type AuditStore struct {
	db     *gorm.DB
	events chan AuditEvent
	done   chan struct{}
}

const auditChannelSize = 4096

// NewAuditStore creates a new audit store, runs migrations, and starts the background worker.
func NewAuditStore(db *gorm.DB) (*AuditStore, error) {
	if err := db.AutoMigrate(&TableAuditLog{}); err != nil {
		return nil, fmt.Errorf("failed to migrate audit logs table: %w", err)
	}
	s := &AuditStore{
		db:     db,
		events: make(chan AuditEvent, auditChannelSize),
		done:   make(chan struct{}),
	}
	go s.worker()
	return s, nil
}

// worker consumes audit events and writes them to the database.
func (s *AuditStore) worker() {
	for event := range s.events {
		entry := &TableAuditLog{
			ID:         uuid.New().String(),
			EventType:  event.EventType,
			Action:     event.Action,
			Status:     event.Status,
			Severity:   event.Severity,
			UserID:     event.UserID,
			UserEmail:  event.UserEmail,
			IP:         event.IP,
			Resource:   event.Resource,
			ResourceID: event.ResourceID,
			Details:    event.Details,
			CreatedAt:  time.Now(),
		}
		if entry.Status == "" {
			entry.Status = StatusSuccess
		}
		if entry.Severity == "" {
			entry.Severity = SeverityLow
		}
		if entry.EventType == "" {
			entry.EventType = EventTypeConfigurationChange
		}
		if err := s.db.Create(entry).Error; err != nil {
			log.Printf("[audit] failed to persist: %v", err)
		}
	}
	close(s.done)
}

// Emit sends an audit event to the background worker.
func (s *AuditStore) Emit(event AuditEvent) {
	select {
	case s.events <- event:
	default:
		log.Printf("[audit] channel full, dropping: %s %s", event.Action, event.Resource)
	}
}

// Close drains the channel and waits for the worker to finish.
func (s *AuditStore) Close() {
	close(s.events)
	<-s.done
}

// ClearAll deletes all audit logs.
func (s *AuditStore) ClearAll(ctx context.Context) error {
	return s.db.WithContext(ctx).Where("1 = 1").Delete(&TableAuditLog{}).Error
}

// RecentActivity returns the most recent audit log entries.
func (s *AuditStore) RecentActivity(ctx context.Context, limit int) ([]TableAuditLog, error) {
	if limit == 0 {
		limit = 10
	}
	var logs []TableAuditLog
	if err := s.db.WithContext(ctx).Order("created_at DESC").Limit(limit).Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}

// AuditLogQuery defines query parameters for audit logs.
type AuditLogQuery struct {
	EventType string
	Action    string
	Status    string
	Severity  string
	UserID    string
	Resource  string
	Search    string
	StartAt   *time.Time
	EndAt     *time.Time
	Offset    int
	Limit     int
}

// Query retrieves audit logs with filtering.
func (s *AuditStore) Query(ctx context.Context, q AuditLogQuery) ([]TableAuditLog, int64, error) {
	var logs []TableAuditLog
	var total int64

	query := s.db.WithContext(ctx).Model(&TableAuditLog{})
	if q.EventType != "" {
		query = query.Where("event_type = ?", q.EventType)
	}
	if q.Action != "" {
		query = query.Where("action = ?", q.Action)
	}
	if q.Status != "" {
		query = query.Where("status = ?", q.Status)
	}
	if q.Severity != "" {
		query = query.Where("severity = ?", q.Severity)
	}
	if q.UserID != "" {
		query = query.Where("user_id = ?", q.UserID)
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
		query = query.Where("user_email LIKE ? OR details LIKE ? OR action LIKE ?", "%"+q.Search+"%", "%"+q.Search+"%", "%"+q.Search+"%")
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

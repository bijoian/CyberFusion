package domain

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GeoLocation represents geographical information
type GeoLocation struct {
	Latitude  float64 `gorm:"column:latitude" json:"latitude"`
	Longitude float64 `gorm:"column:longitude" json:"longitude"`
	Country   string  `gorm:"column:country" json:"country"`
	City      string  `gorm:"column:city" json:"city"`
	Region    string  `gorm:"column:region" json:"region"`
}

// Asset represents a network asset (host, service, etc)
type Asset struct {
	ID         string         `gorm:"primaryKey" json:"id"`
	ScanID     string         `gorm:"index" json:"scan_id"`
	HostName   string         `gorm:"index" json:"hostname"`
	IPAddress  string         `gorm:"index" json:"ip_address"`
	MACAddress string         `json:"mac_address"`
	OS         string         `json:"os"`
	OSVersion  string         `json:"os_version"`
	Location   GeoLocation    `gorm:"embedded" json:"location"`
	IsActive   bool           `json:"is_active"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Findings   []Finding      `gorm:"foreignKey:AssetID" json:"findings,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// Service represents a detected service
type Service struct {
	ID          string    `gorm:"primaryKey" json:"id"`
	AssetID     string    `gorm:"index" json:"asset_id"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Banner      string    `json:"banner"`
	State       string    `json:"state"` // open, closed, filtered
	Fingerprint string    `json:"fingerprint"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	ID          string    `gorm:"primaryKey" json:"id"`
	CVE         string    `gorm:"index" json:"cve"`
	CWE         string    `json:"cwe"`
	CVEs        []string  `gorm:"serializer:json" json:"cves"`
	CWEs        []string  `gorm:"serializer:json" json:"cwes"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	CVSS        float32   `json:"cvss"`
	CVSSVector  string    `json:"cvss_vector"`
	Severity    string    `json:"severity"` // critical, high, medium, low, info
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Finding represents a security finding
type Finding struct {
	ID              string            `gorm:"primaryKey" json:"id"`
	ScanID          string            `gorm:"index" json:"scan_id"`
	AssetID         string            `gorm:"index" json:"asset_id"`
	Asset           *Asset            `gorm:"foreignKey:AssetID" json:"asset,omitempty"`
	ServiceID       string            `json:"service_id"`
	VulnerabilityID string            `gorm:"index" json:"vulnerability_id"`
	Vulnerability   *Vulnerability    `gorm:"foreignKey:VulnerabilityID" json:"vulnerability,omitempty"`
	FindingType     string            `json:"finding_type"` // vulnerability, misconfiguration, weak_auth, etc
	TemplateID      string            `gorm:"index" json:"template_id"`
	TemplatePath    string            `json:"template_path"`
	TemplateName    string            `json:"template_name"`
	Host            string            `json:"host"`
	MatchedAt       string            `json:"matched_at"`
	Protocol        string            `json:"protocol"`
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	Severity        string            `json:"severity"`   // critical, high, medium, low, info
	Confidence      int               `json:"confidence"` // 0-100
	Status          string            `json:"status"`     // open, acknowledged, remediated, false_positive
	Evidence        string            `json:"evidence"`
	Remediation     string            `json:"remediation"`
	Sources         []string          `gorm:"serializer:json" json:"sources"` // Tools that found this
	References      []string          `gorm:"serializer:json" json:"references"`
	Classification  map[string]string `gorm:"serializer:json" json:"classification"`
	FirstSeen       time.Time         `json:"first_seen"`
	LastSeen        time.Time         `json:"last_seen"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	DeletedAt       gorm.DeletedAt    `gorm:"index" json:"deleted_at,omitempty"`
}

// Scan represents a security scan
type Scan struct {
	ID          string         `gorm:"primaryKey" json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Targets     []string       `gorm:"serializer:json" json:"targets"`
	Status      string         `json:"status"` // pending, running, completed, failed
	StartedAt   *time.Time     `json:"started_at"`
	CompletedAt *time.Time     `json:"completed_at"`
	Duration    int64          `json:"duration_seconds"`
	Assets      []Asset        `gorm:"foreignKey:ScanID" json:"assets,omitempty"`
	Findings    []Finding      `gorm:"foreignKey:ScanID" json:"findings,omitempty"`
	RiskScore   int            `json:"risk_score"`
	Metadata    string         `gorm:"serializer:json" json:"metadata"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// RiskMetrics represents risk analysis for a scan
type RiskMetrics struct {
	ID               string         `gorm:"primaryKey" json:"id"`
	ScanID           string         `gorm:"index" json:"scan_id"`
	TotalAssets      int            `json:"total_assets"`
	VulnerableAssets int            `json:"vulnerable_assets"`
	CriticalCount    int            `json:"critical_count"`
	HighCount        int            `json:"high_count"`
	MediumCount      int            `json:"medium_count"`
	LowCount         int            `json:"low_count"`
	InfoCount        int            `json:"info_count"`
	RiskScore        int            `json:"risk_score"`     // 0-100
	ExposureLevel    string         `json:"exposure_level"` // critical, high, medium, low
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// NewAsset creates a new asset with generated ID
func NewAsset() *Asset {
	return &Asset{
		ID:        uuid.New().String(),
		IsActive:  true,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
}

// NewFinding creates a new finding with generated ID
func NewFinding() *Finding {
	return &Finding{
		ID:        uuid.New().String(),
		Status:    "open",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
}

// NewVulnerability creates a vulnerability with a generated ID.
func NewVulnerability() *Vulnerability {
	return &Vulnerability{
		ID: uuid.New().String(),
	}
}

// NewScan creates a new scan with generated ID
func NewScan() *Scan {
	return &Scan{
		ID:     uuid.New().String(),
		Status: "pending",
	}
}

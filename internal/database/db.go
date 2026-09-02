package database

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bijoian/cyberfusion/internal/domain"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database struct {
	db  *gorm.DB
	log *logrus.Logger
}

// New creates a new database connection
func New(dbPath string, log *logrus.Logger) (*Database, error) {
	if err := createDatabasePath(dbPath); err != nil {
		return nil, fmt.Errorf("failed to create database path: %w", err)
	}

	dsn := filepath.Join(dbPath, "cyberfusion.db")
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-migrate models
	if err := db.AutoMigrate(
		&domain.Scan{},
		&domain.Asset{},
		&domain.Service{},
		&domain.Vulnerability{},
		&domain.Finding{},
		&domain.RiskMetrics{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &Database{
		db:  db,
		log: log,
	}, nil
}

// GetDB returns the underlying GORM DB instance
func (d *Database) GetDB() *gorm.DB {
	return d.db
}

// Close closes the database connection
func (d *Database) Close() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Ping tests the database connection
func (d *Database) Ping() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

func createDatabasePath(dbPath string) error {
	return os.MkdirAll(dbPath, 0o750)
}

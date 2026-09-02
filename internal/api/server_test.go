package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bijoian/cyberfusion/internal/authorization"
	"github.com/bijoian/cyberfusion/internal/domain"
	"github.com/bijoian/cyberfusion/internal/orchestrator"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestHealth(t *testing.T) {
	server, _ := newTestServer(t)
	response := request(server, http.MethodGet, "/api/v1/health", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", response.Code, http.StatusOK)
	}
	var body map[string]string
	decodeBody(t, response, &body)
	if body["status"] != "ok" {
		t.Errorf("health status body = %q, want ok", body["status"])
	}
}

func TestCreateScanRequiresAuthorizedTarget(t *testing.T) {
	server, _ := newTestServer(t)
	response := request(server, http.MethodPost, "/api/v1/scans", []byte(`{"targets":["192.0.2.10"]}`))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("create status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	var body errorResponse
	decodeBody(t, response, &body)
	if body.Error.Code != "invalid_request" {
		t.Errorf("error code = %q, want invalid_request", body.Error.Code)
	}
}

func TestCreateScanPersistsAuthorizedScan(t *testing.T) {
	server, db := newTestServer(t)
	response := request(server, http.MethodPost, "/api/v1/scans", []byte(`{"name":"authorized scan","targets":["10.42.0.10"]}`))

	if response.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, want %d: %s", response.Code, http.StatusAccepted, response.Body.String())
	}
	var scan domain.Scan
	decodeBody(t, response, &scan)
	if len(scan.Targets) != 1 || scan.Targets[0] != "10.42.0.10" {
		t.Fatalf("scan targets = %v, want [10.42.0.10]", scan.Targets)
	}

	deadline := time.Now().Add(time.Second)
	for {
		var persisted domain.Scan
		if err := db.First(&persisted, "id = ?", scan.ID).Error; err != nil {
			t.Fatalf("loading scan: %v", err)
		}
		if persisted.Status == "completed" {
			var assetCount int64
			if err := db.Model(&domain.Asset{}).Where("scan_id = ?", scan.ID).Count(&assetCount).Error; err != nil {
				t.Fatalf("counting assets: %v", err)
			}
			if assetCount != 1 {
				t.Errorf("asset count = %d, want 1", assetCount)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("scan status = %q, want completed", persisted.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFindingsAndAssetsSupportFilteringPaginationAndDetail(t *testing.T) {
	server, db := newTestServer(t)
	scan := domain.NewScan()
	scan.Status = "completed"
	if err := db.Create(scan).Error; err != nil {
		t.Fatalf("creating scan: %v", err)
	}
	asset := domain.NewAsset()
	asset.ScanID = scan.ID
	asset.HostName = "app.example.test"
	asset.IPAddress = "10.42.0.20"
	if err := db.Create(asset).Error; err != nil {
		t.Fatalf("creating asset: %v", err)
	}
	finding := domain.NewFinding()
	finding.ScanID = scan.ID
	finding.AssetID = asset.ID
	finding.Severity = "high"
	finding.Title = "Exposed service"
	if err := db.Create(finding).Error; err != nil {
		t.Fatalf("creating finding: %v", err)
	}

	findingsResponse := request(server, http.MethodGet, "/api/v1/findings?scan_id="+scan.ID+"&severity=high&limit=1", nil)
	if findingsResponse.Code != http.StatusOK {
		t.Fatalf("findings status = %d, want %d", findingsResponse.Code, http.StatusOK)
	}
	var findings collectionResponse[domain.Finding]
	decodeBody(t, findingsResponse, &findings)
	if findings.Pagination.Total != 1 || len(findings.Items) != 1 || findings.Items[0].ID != finding.ID {
		t.Errorf("findings response = %#v, want one matching finding", findings)
	}

	assetResponse := request(server, http.MethodGet, "/api/v1/assets/"+asset.ID, nil)
	if assetResponse.Code != http.StatusOK {
		t.Fatalf("asset status = %d, want %d", assetResponse.Code, http.StatusOK)
	}
	var detailedAsset domain.Asset
	decodeBody(t, assetResponse, &detailedAsset)
	if len(detailedAsset.Findings) != 1 || detailedAsset.Findings[0].ID != finding.ID {
		t.Errorf("asset findings = %#v, want finding %s", detailedAsset.Findings, finding.ID)
	}
}

func newTestServer(t *testing.T) (*Server, *gorm.DB) {
	t.Helper()
	dsn := fmt.Sprintf("file:api-test-%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	if err := db.AutoMigrate(&domain.Scan{}, &domain.Asset{}, &domain.Service{}, &domain.Vulnerability{}, &domain.Finding{}, &domain.RiskMetrics{}); err != nil {
		t.Fatalf("migrating database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("retrieving SQL database: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	authorizer, err := authorization.NewTargetAuthorizer([]string{"10.42.0.0/16", "example.test"})
	if err != nil {
		t.Fatalf("creating authorizer: %v", err)
	}
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)
	server, err := NewServer(Config{
		DB:           db,
		Orchestrator: orchestrator.New(log),
		Authorizer:   authorizer,
		Logger:       log,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	return server, db
}

func request(server *Server, method, path string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func decodeBody(t *testing.T, response *httptest.ResponseRecorder, destination interface{}) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatalf("decoding response body: %v", err)
	}
}

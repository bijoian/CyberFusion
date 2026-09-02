// Package api exposes read-only scan data and authorized scan creation for the
// Control layer.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bijoian/cyberfusion/internal/authorization"
	"github.com/bijoian/cyberfusion/internal/domain"
	"github.com/bijoian/cyberfusion/internal/orchestrator"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const (
	apiPrefix          = "/api/v1"
	defaultPageSize    = 50
	maxPageSize        = 100
	defaultScanTimeout = 300
	defaultScanThreads = 10
	maxScanTimeout     = 3600
	maxScanThreads     = 64
	maxScanTargets     = 100
	maxRequestBody     = 1 << 20
)

// Config configures a Server.
type Config struct {
	DB           *gorm.DB
	Orchestrator *orchestrator.Orchestrator
	Authorizer   *authorization.TargetAuthorizer
	Logger       *logrus.Logger
}

// Server implements the versioned Control REST API.
type Server struct {
	db           *gorm.DB
	orchestrator *orchestrator.Orchestrator
	authorizer   *authorization.TargetAuthorizer
	log          *logrus.Logger
	scanContext  context.Context
	cancelScans  context.CancelFunc
	scanWG       sync.WaitGroup
}

// NewServer constructs an API server with the dependencies required to create
// and retrieve scans.
func NewServer(config Config) (*Server, error) {
	if config.DB == nil {
		return nil, fmt.Errorf("database is required")
	}
	if config.Orchestrator == nil {
		return nil, fmt.Errorf("orchestrator is required")
	}
	if config.Authorizer == nil {
		return nil, fmt.Errorf("target authorizer is required")
	}
	if config.Logger == nil {
		config.Logger = logrus.New()
	}

	scanContext, cancelScans := context.WithCancel(context.Background())
	return &Server{
		db:           config.DB,
		orchestrator: config.Orchestrator,
		authorizer:   config.Authorizer,
		log:          config.Logger,
		scanContext:  scanContext,
		cancelScans:  cancelScans,
	}, nil
}

// Handler returns the HTTP handler for the API.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.ServeHTTP)
}

// Shutdown stops active scan work and waits for worker completion.
func (s *Server) Shutdown(ctx context.Context) error {
	s.cancelScans()
	done := make(chan struct{})
	go func() {
		s.scanWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ServeHTTP routes API requests and ensures failures retain the JSON error
// contract.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.log.Errorf("API panic: %v", recovered)
			writeError(w, http.StatusInternalServerError, "internal_error", "an internal error occurred")
		}
	}()

	switch {
	case r.URL.Path == apiPrefix+"/health":
		s.handleHealth(w, r)
	case r.URL.Path == apiPrefix+"/scans":
		s.handleScans(w, r)
	case strings.HasPrefix(r.URL.Path, apiPrefix+"/scans/"):
		s.handleScan(w, r, strings.TrimPrefix(r.URL.Path, apiPrefix+"/scans/"))
	case r.URL.Path == apiPrefix+"/findings":
		s.handleFindings(w, r)
	case strings.HasPrefix(r.URL.Path, apiPrefix+"/findings/"):
		s.handleFinding(w, r, strings.TrimPrefix(r.URL.Path, apiPrefix+"/findings/"))
	case r.URL.Path == apiPrefix+"/assets":
		s.handleAssets(w, r)
	case strings.HasPrefix(r.URL.Path, apiPrefix+"/assets/"):
		s.handleAsset(w, r, strings.TrimPrefix(r.URL.Path, apiPrefix+"/assets/"))
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if err := s.databaseHealth(r.Context()); err != nil {
		s.log.Errorf("API health check failed: %v", err)
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "database is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listScans(w, r)
	case http.MethodPost:
		s.createScan(w, r)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !validResourceID(id) {
		writeError(w, http.StatusNotFound, "not_found", "scan not found")
		return
	}

	var scan domain.Scan
	if err := s.db.WithContext(r.Context()).First(&scan, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			writeError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		s.databaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	page, ok := parsePagination(w, r)
	if !ok {
		return
	}
	query := s.db.WithContext(r.Context()).Model(&domain.Scan{})
	if status := r.URL.Query().Get("status"); status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		s.databaseError(w, err)
		return
	}
	var scans []domain.Scan
	if err := query.Order("created_at DESC").Limit(page.Limit).Offset(page.Offset).Find(&scans).Error; err != nil {
		s.databaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, collectionResponse[domain.Scan]{Items: scans, Pagination: page.withTotal(total)})
}

type createScanRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Targets        []string `json:"targets"`
	Modules        []string `json:"modules"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Threads        int      `json:"threads"`
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var request createScanRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	if err := ensureSingleJSONValue(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must contain one JSON object")
		return
	}

	normalizedTargets, err := s.validateScanRequest(&request)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	scan := domain.NewScan()
	scan.Name = strings.TrimSpace(request.Name)
	scan.Description = strings.TrimSpace(request.Description)
	scan.Targets = normalizedTargets
	scan.Status = "pending"
	if err := s.db.WithContext(r.Context()).Create(scan).Error; err != nil {
		s.databaseError(w, err)
		return
	}

	executionScan := *scan
	config := orchestrator.ScanConfig{
		Targets:  normalizedTargets,
		Modules:  request.Modules,
		Timeout:  time.Duration(request.TimeoutSeconds) * time.Second,
		Threads:  request.Threads,
	}
	s.scanWG.Add(1)
	go func() {
		defer s.scanWG.Done()
		s.executeScan(&executionScan, config)
	}()

	writeJSON(w, http.StatusAccepted, scan)
}

func (s *Server) validateScanRequest(request *createScanRequest) ([]string, error) {
	if len(request.Name) > 255 {
		return nil, fmt.Errorf("name must not exceed 255 characters")
	}
	if len(request.Description) > 2000 {
		return nil, fmt.Errorf("description must not exceed 2000 characters")
	}
	if len(request.Targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	if len(request.Targets) > maxScanTargets {
		return nil, fmt.Errorf("at most %d targets are allowed", maxScanTargets)
	}
	if request.TimeoutSeconds == 0 {
		request.TimeoutSeconds = defaultScanTimeout
	}
	if request.TimeoutSeconds < 1 || request.TimeoutSeconds > maxScanTimeout {
		return nil, fmt.Errorf("timeout_seconds must be between 1 and %d", maxScanTimeout)
	}
	if request.Threads == 0 {
		request.Threads = defaultScanThreads
	}
	if request.Threads < 1 || request.Threads > maxScanThreads {
		return nil, fmt.Errorf("threads must be between 1 and %d", maxScanThreads)
	}
	if len(request.Modules) == 0 {
		request.Modules = []string{"port_scan", "service_detection"}
	}
	allowedModules := map[string]struct{}{"port_scan": {}, "service_detection": {}}
	for _, module := range request.Modules {
		if _, ok := allowedModules[module]; !ok {
			return nil, fmt.Errorf("unsupported module %q", module)
		}
	}

	normalized := make([]string, 0, len(request.Targets))
	seen := make(map[string]struct{})
	for _, target := range request.Targets {
		authorizedTarget, err := s.authorizer.Authorize(target)
		if err != nil {
			return nil, fmt.Errorf("target %q is not authorized: %w", target, err)
		}
		if _, exists := seen[authorizedTarget]; exists {
			return nil, fmt.Errorf("target %q is duplicated", target)
		}
		seen[authorizedTarget] = struct{}{}
		normalized = append(normalized, authorizedTarget)
	}
	return normalized, nil
}

func (s *Server) executeScan(scan *domain.Scan, config orchestrator.ScanConfig) {
	ctx, cancel := context.WithTimeout(s.scanContext, config.Timeout)
	defer cancel()

	startedAt := time.Now()
	if err := s.db.Model(&domain.Scan{}).Where("id = ?", scan.ID).Updates(map[string]interface{}{
		"status":     "running",
		"started_at": &startedAt,
	}).Error; err != nil {
		s.log.Errorf("failed to mark scan %s as running: %v", scan.ID, err)
		s.markScanFailed(scan.ID)
		return
	}

	result, err := s.orchestrator.ExecuteScanFor(ctx, scan, config)
	if err != nil {
		s.markScanFailed(scan.ID)
		s.log.Errorf("scan %s failed: %v", scan.ID, err)
		return
	}

	transaction := s.db.Begin()
	if transaction.Error != nil {
		s.log.Errorf("failed to begin scan %s persistence transaction: %v", scan.ID, transaction.Error)
		return
	}
	if err := transaction.Save(result.Scan).Error; err == nil {
		for index := range result.Assets {
			result.Assets[index].ScanID = scan.ID
			if err = transaction.Create(&result.Assets[index]).Error; err != nil {
				break
			}
		}
	}
	if err == nil {
		for index := range result.Findings {
			result.Findings[index].ScanID = scan.ID
			if err = transaction.Create(&result.Findings[index]).Error; err != nil {
				break
			}
		}
	}
	if err != nil {
		transaction.Rollback()
		s.markScanFailed(scan.ID)
		s.log.Errorf("failed to save scan %s results: %v", scan.ID, err)
		return
	}
	if err := transaction.Commit().Error; err != nil {
		s.markScanFailed(scan.ID)
		s.log.Errorf("failed to commit scan %s results: %v", scan.ID, err)
	}
}

func (s *Server) markScanFailed(scanID string) {
	now := time.Now()
	if err := s.db.Model(&domain.Scan{}).Where("id = ?", scanID).Updates(map[string]interface{}{
		"status":       "failed",
		"completed_at": &now,
	}).Error; err != nil {
		s.log.Errorf("failed to record scan %s failure: %v", scanID, err)
	}
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	page, ok := parsePagination(w, r)
	if !ok {
		return
	}
	query := s.db.WithContext(r.Context()).Model(&domain.Finding{})
	for _, filter := range []struct{ key, column string }{
		{"scan_id", "scan_id"}, {"asset_id", "asset_id"}, {"severity", "severity"}, {"status", "status"},
	} {
		if value := r.URL.Query().Get(filter.key); value != "" {
			query = query.Where(filter.column+" = ?", value)
		}
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		s.databaseError(w, err)
		return
	}
	var findings []domain.Finding
	if err := query.Preload("Asset").Preload("Vulnerability").Order("created_at DESC").Limit(page.Limit).Offset(page.Offset).Find(&findings).Error; err != nil {
		s.databaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, collectionResponse[domain.Finding]{Items: findings, Pagination: page.withTotal(total)})
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !validResourceID(id) {
		writeError(w, http.StatusNotFound, "not_found", "finding not found")
		return
	}
	var finding domain.Finding
	if err := s.db.WithContext(r.Context()).Preload("Asset").Preload("Vulnerability").First(&finding, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			writeError(w, http.StatusNotFound, "not_found", "finding not found")
			return
		}
		s.databaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, finding)
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	page, ok := parsePagination(w, r)
	if !ok {
		return
	}
	query := s.db.WithContext(r.Context()).Model(&domain.Asset{})
	for _, filter := range []struct{ key, column string }{
		{"scan_id", "scan_id"}, {"hostname", "host_name"}, {"ip_address", "ip_address"},
	} {
		if value := r.URL.Query().Get(filter.key); value != "" {
			query = query.Where(filter.column+" = ?", value)
		}
	}
	if active := r.URL.Query().Get("active"); active != "" {
		isActive, err := strconv.ParseBool(active)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "active must be a boolean")
			return
		}
		query = query.Where("is_active = ?", isActive)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		s.databaseError(w, err)
		return
	}
	var assets []domain.Asset
	if err := query.Order("created_at DESC").Limit(page.Limit).Offset(page.Offset).Find(&assets).Error; err != nil {
		s.databaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, collectionResponse[domain.Asset]{Items: assets, Pagination: page.withTotal(total)})
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !validResourceID(id) {
		writeError(w, http.StatusNotFound, "not_found", "asset not found")
		return
	}
	var asset domain.Asset
	if err := s.db.WithContext(r.Context()).Preload("Findings").First(&asset, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			writeError(w, http.StatusNotFound, "not_found", "asset not found")
			return
		}
		s.databaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, asset)
}

func (s *Server) databaseHealth(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

func (s *Server) databaseError(w http.ResponseWriter, err error) {
	s.log.Errorf("database error: %v", err)
	writeError(w, http.StatusInternalServerError, "database_error", "database operation failed")
}

type pagination struct {
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
	Total  int64 `json:"total"`
}

func parsePagination(w http.ResponseWriter, r *http.Request) (pagination, bool) {
	page := pagination{Limit: defaultPageSize}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > maxPageSize {
			writeError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("limit must be between 1 and %d", maxPageSize))
			return pagination{}, false
		}
		page.Limit = limit
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", "offset must be a non-negative integer")
			return pagination{}, false
		}
		page.Offset = offset
	}
	return page, true
}

func (p pagination) withTotal(total int64) pagination {
	p.Total = total
	return p
}

type collectionResponse[T any] struct {
	Items      []T        `json:"items"`
	Pagination pagination `json:"pagination"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: apiError{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

func ensureSingleJSONValue(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func validResourceID(id string) bool {
	return id != "" && !strings.Contains(id, "/")
}

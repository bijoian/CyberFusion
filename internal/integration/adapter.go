package integration

import (
	"context"

	"github.com/bijoian/cyberfusion/internal/domain"
)

// ScannerAdapter defines the interface for external scanners
type ScannerAdapter interface {
	Name() string
	Scan(ctx context.Context, target string, options map[string]interface{}) ([]domain.Finding, error)
	SupportsProtocol(protocol string) bool
	Version() string
}

// Registry holds all registered scanners
type Registry struct {
	scanners map[string]ScannerAdapter
}

// NewRegistry creates a new scanner registry
func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[string]ScannerAdapter),
	}
}

// Register registers a scanner adapter
func (r *Registry) Register(adapter ScannerAdapter) {
	r.scanners[adapter.Name()] = adapter
}

// Get retrieves a scanner adapter by name
func (r *Registry) Get(name string) (ScannerAdapter, bool) {
	scanner, ok := r.scanners[name]
	return scanner, ok
}

// List returns all registered scanner names
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	return names
}

package authorization

import (
	"fmt"
	"net/netip"
	"strings"
)

// TargetAuthorizer permits scans only for explicitly configured targets.
type TargetAuthorizer struct {
	entries []entry
}

type entry struct {
	value  string
	kind   entryKind
	addr   netip.Addr
	prefix netip.Prefix
}

type entryKind uint8

const (
	hostEntry entryKind = iota
	addressEntry
	prefixEntry
)

// NewTargetAuthorizer builds an authorizer from hostnames, IP addresses, and
// CIDR ranges. Broad CIDR ranges are rejected to avoid accidental global scans.
func NewTargetAuthorizer(targets []string) (*TargetAuthorizer, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one authorized target is required")
	}

	authorizer := &TargetAuthorizer{}
	seen := make(map[string]struct{})
	for _, target := range targets {
		parsed, err := parseEntry(target)
		if err != nil {
			return nil, fmt.Errorf("invalid authorized target %q: %w", target, err)
		}
		if _, ok := seen[parsed.value]; ok {
			continue
		}
		seen[parsed.value] = struct{}{}
		authorizer.entries = append(authorizer.entries, parsed)
	}

	return authorizer, nil
}

// Authorize normalizes target and verifies it is explicitly authorized.
func (a *TargetAuthorizer) Authorize(target string) (string, error) {
	if a == nil {
		return "", fmt.Errorf("target authorization is not configured")
	}

	requested, err := parseEntry(target)
	if err != nil {
		return "", err
	}

	for _, allowed := range a.entries {
		switch {
		case allowed.kind == hostEntry && requested.kind == hostEntry && allowed.value == requested.value:
			return requested.value, nil
		case allowed.kind == addressEntry && requested.kind == addressEntry && allowed.addr == requested.addr:
			return requested.value, nil
		case allowed.kind == prefixEntry && requested.kind == addressEntry && allowed.prefix.Contains(requested.addr):
			return requested.value, nil
		case allowed.kind == prefixEntry && requested.kind == prefixEntry && allowed.prefix == requested.prefix:
			return requested.value, nil
		}
	}

	return "", fmt.Errorf("target is not in the authorized target list")
}

func parseEntry(raw string) (entry, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return entry{}, fmt.Errorf("target is required")
	}

	if prefix, err := netip.ParsePrefix(value); err == nil {
		if prefix != prefix.Masked() {
			return entry{}, fmt.Errorf("CIDR target must be a network address")
		}
		if (prefix.Addr().Is4() && prefix.Bits() < 8) || (prefix.Addr().Is6() && prefix.Bits() < 32) {
			return entry{}, fmt.Errorf("CIDR range is too broad")
		}
		return entry{value: prefix.String(), kind: prefixEntry, prefix: prefix}, nil
	}

	if addr, err := netip.ParseAddr(value); err == nil {
		return entry{value: addr.String(), kind: addressEntry, addr: addr}, nil
	}

	if !isHostname(value) {
		return entry{}, fmt.Errorf("target must be an IP address, CIDR range, or hostname")
	}
	return entry{value: value, kind: hostEntry}, nil
}

func isHostname(value string) bool {
	if len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}

	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

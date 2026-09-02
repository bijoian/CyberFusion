package nmap

import "github.com/sirupsen/logrus"

const (
	AdapterName = "nmap"
	Version     = "1.0.0"
)

// NmapAdapter wraps nmap for CyberFusion
type NmapAdapter struct {
	log *logrus.Logger
}

// New creates a new nmap adapter
func New(log *logrus.Logger) *NmapAdapter {
	return &NmapAdapter{
		log: log,
	}
}

// Name returns the adapter name
func (n *NmapAdapter) Name() string {
	return AdapterName
}

// Version returns the adapter version
func (n *NmapAdapter) Version() string {
	return Version
}

// SupportsProtocol checks if nmap supports a protocol
func (n *NmapAdapter) SupportsProtocol(protocol string) bool {
	protocols := map[string]bool{
		"tcp":  true,
		"udp":  true,
		"icmp": true,
	}
	return protocols[protocol]
}

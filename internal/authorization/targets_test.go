package authorization

import "testing"

func TestTargetAuthorizerAuthorize(t *testing.T) {
	authorizer, err := NewTargetAuthorizer([]string{"Example.COM", "10.42.0.0/16", "2001:db8::1"})
	if err != nil {
		t.Fatalf("NewTargetAuthorizer() error = %v", err)
	}

	tests := []struct {
		name    string
		target  string
		want    string
		wantErr bool
	}{
		{name: "normalized hostname", target: "example.com", want: "example.com"},
		{name: "address in CIDR", target: "10.42.10.20", want: "10.42.10.20"},
		{name: "exact IPv6 address", target: "2001:db8::1", want: "2001:db8::1"},
		{name: "unauthorized address", target: "10.43.10.20", wantErr: true},
		{name: "URL is rejected", target: "https://example.com", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := authorizer.Authorize(test.target)
			if (err != nil) != test.wantErr {
				t.Fatalf("Authorize() error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("Authorize() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestTargetAuthorizerRejectsBroadCIDR(t *testing.T) {
	if _, err := NewTargetAuthorizer([]string{"0.0.0.0/0"}); err == nil {
		t.Fatal("NewTargetAuthorizer() accepted an unsafe broad CIDR")
	}
}

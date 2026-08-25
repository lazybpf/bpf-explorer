package main

import "testing"

// TestLocalTarget covers the wildcard-to-localhost rewrite: the UI half of
// --role=local has to dial the agent half, and a wildcard listen address is not
// something you can dial.
func TestLocalTarget(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"port only", ":50051", "localhost:50051"},
		{"ipv4 wildcard", "0.0.0.0:50051", "localhost:50051"},
		{"ipv6 wildcard", "[::]:50051", "localhost:50051"},
		{"explicit loopback kept", "127.0.0.1:50051", "127.0.0.1:50051"},
		{"explicit host kept", "localhost:9999", "localhost:9999"},
		{"ipv6 literal kept bracketed", "[::1]:50051", "[::1]:50051"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := localTarget(tc.in)
			if err != nil {
				t.Fatalf("localTarget(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("localTarget(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestLocalTargetErrors(t *testing.T) {
	for _, in := range []string{"", "50051", "localhost", ":"} {
		if got, err := localTarget(in); err == nil {
			t.Errorf("localTarget(%q) = %q, want error", in, got)
		}
	}
}

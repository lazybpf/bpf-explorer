package inspector

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBootTimeAgreesWithProcUptime checks the clock the dates rest on: a boot
// instant that is wrong by an hour dates every program on the node wrong by an
// hour, and nothing downstream could tell. /proc/uptime counts from the same
// boottime clock, so the two have to land on the same instant.
func TestBootTimeAgreesWithProcUptime(t *testing.T) {
	boot, ok := bootTime()
	if !ok {
		t.Skip("CLOCK_BOOTTIME unavailable")
	}

	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		t.Skipf("no /proc/uptime: %v", err)
	}
	field, _, _ := strings.Cut(strings.TrimSpace(string(raw)), " ")
	secs, err := strconv.ParseFloat(field, 64)
	if err != nil {
		t.Fatalf("parse %q: %v", field, err)
	}

	want := time.Now().Add(-time.Duration(secs * float64(time.Second)))
	// Loose: the two clocks are read a moment apart, and /proc/uptime is
	// rounded to a hundredth of a second. Wide enough not to flake, tight
	// enough to catch a unit or sign error.
	if diff := boot.Sub(want); diff > 2*time.Second || diff < -2*time.Second {
		t.Errorf("bootTime is %v off /proc/uptime's boot instant", diff)
	}
	if boot.After(time.Now()) {
		t.Errorf("bootTime is in the future: %v", boot)
	}
}

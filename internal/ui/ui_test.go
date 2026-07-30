package ui

import "testing"

func TestParseHiddenLoaderPIDs(t *testing.T) {
	if got := parseHiddenLoaderPIDs(""); got != nil {
		t.Errorf("empty spec: want nil, got %v", got)
	}
	got := parseHiddenLoaderPIDs("1, 2 ,bad,,3")
	if len(got) != 3 || !got[1] || !got[2] || !got[3] {
		t.Errorf("want {1,2,3} (bad/blank skipped), got %v", got)
	}
}

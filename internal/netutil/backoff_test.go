package netutil

import (
	"testing"
	"time"
)

func TestBackoffCapsAndResets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backoff Backoff
		wantMS  []int
	}{
		{
			name:   "zero value",
			wantMS: []int{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000, 1000},
		},
		{
			name:    "custom cap",
			backoff: Backoff{MinDelay: 20 * time.Millisecond, MaxDelay: 75 * time.Millisecond},
			wantMS:  []int{20, 40, 75, 75, 75},
		},
		{
			name:    "cap below minimum",
			backoff: Backoff{MinDelay: 50 * time.Millisecond, MaxDelay: 20 * time.Millisecond},
			wantMS:  []int{20, 20, 20},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, wantMS := range tc.wantMS {
				want := time.Duration(wantMS) * time.Millisecond
				got := tc.backoff.Backoff()
				if tc.backoff.tempDelay != want {
					t.Fatalf("call %d: base delay = %v, want %v", i+1, tc.backoff.tempDelay, want)
				}
				if got < want || got >= want+334*time.Millisecond {
					t.Fatalf("call %d: delay = %v, want [%v, %v)", i+1, got, want, want+334*time.Millisecond)
				}
			}
			tc.backoff.Reset()
			want := time.Duration(tc.wantMS[0]) * time.Millisecond
			tc.backoff.Backoff()
			if tc.backoff.tempDelay != want {
				t.Fatalf("base delay after Reset = %v, want %v", tc.backoff.tempDelay, want)
			}
		})
	}
}

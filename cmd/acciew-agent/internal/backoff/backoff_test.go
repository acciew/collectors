package backoff_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/backoff"
)

func TestTheDelayDoublesWithJitterAndStopsAtTheCap(t *testing.T) {
	p := backoff.Policy{Min: time.Second, Max: 2 * time.Minute}
	prev := time.Duration(0)
	for attempt := range 12 {
		for range 50 {
			d := p.Delay(attempt)
			ceiling := min(p.Max, p.Min<<uint(min(attempt, 20)))
			if d < ceiling/2 || d > ceiling {
				t.Fatalf("attempt %d: %v is outside [%v, %v]", attempt, d, ceiling/2, ceiling)
			}
		}
		_ = prev
	}
	if d := p.Delay(100); d > p.Max || d < p.Max/2 {
		t.Errorf("a long outage: %v, cap %v", d, p.Max)
	}
}

// Agents that lost the network together must not come back together.
func TestTwoAgentsDoNotWaitTheSameTime(t *testing.T) {
	p := backoff.Policy{Min: time.Second, Max: time.Minute}
	seen := map[time.Duration]bool{}
	for range 20 {
		seen[p.Delay(3)] = true
	}
	if len(seen) < 5 {
		t.Errorf("only %d different delays in 20 draws", len(seen))
	}
}

func TestSleepEndsWhenTheContextDoes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := backoff.Sleep(ctx, time.Hour); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Errorf("err %v after %v", err, time.Since(start))
	}
	if err := backoff.Sleep(context.Background(), time.Millisecond); err != nil {
		t.Error(err)
	}
}

func TestAZeroPolicyStillWaitsSomething(t *testing.T) {
	if d := (backoff.Policy{}).Delay(0); d <= 0 {
		t.Errorf("a zero policy gave %v: that is a tight loop", d)
	}
}

// A policy nobody filled in must not collapse to one second: chunk retries against a service
// that is failing would then run every half second for ten minutes.
func TestAZeroOrHalfFilledPolicyBacksOffAsTheDefaultsDo(t *testing.T) {
	for _, p := range []backoff.Policy{{}, {Min: time.Second}, {Max: 2 * time.Minute}} {
		for attempt := range 12 {
			ceiling := min(backoff.Defaults.Max, backoff.Defaults.Min<<uint(min(attempt, 20)))
			for range 30 {
				if d := p.Delay(attempt); d < ceiling/2 || d > ceiling {
					t.Fatalf("%+v attempt %d: %v is outside [%v, %v]", p, attempt, d, ceiling/2, ceiling)
				}
			}
		}
	}
}

func TestTheDefaultScheduleIsASecondDoublingToTwoMinutes(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 16, 32, 64, 120, 120, 120}
	for attempt, secs := range want {
		ceiling := secs * time.Second
		for range 30 {
			if d := backoff.Defaults.Delay(attempt); d < ceiling/2 || d > ceiling {
				t.Fatalf("attempt %d: %v is outside [%v, %v]", attempt, d, ceiling/2, ceiling)
			}
		}
	}
}

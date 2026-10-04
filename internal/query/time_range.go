package query

import (
	"fmt"
	"time"
)

// TimeRange uses a supported relative duration or RFC3339 bounds: from <= @timestamp < to.
type TimeRange struct {
	Relative string `json:"relative,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
}

func resolveTimeRange(input *TimeRange, now time.Time) (*TimeRange, error) {
	if input == nil {
		return nil, nil
	}
	var from, to time.Time
	if input.Relative != "" {
		if input.From != "" || input.To != "" {
			return nil, fmt.Errorf("time_range must use relative or absolute bounds, not both")
		}
		durations := map[string]time.Duration{"15m": 15 * time.Minute, "1h": time.Hour, "4h": 4 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}
		duration, ok := durations[input.Relative]
		if !ok {
			return nil, fmt.Errorf("unsupported relative time_range %q", input.Relative)
		}
		to = now.UTC()
		from = to.Add(-duration)
	} else {
		var err error
		from, err = time.Parse(time.RFC3339Nano, input.From)
		if err != nil {
			return nil, fmt.Errorf("time_range.from must be an RFC3339 timestamp with timezone")
		}
		to, err = time.Parse(time.RFC3339Nano, input.To)
		if err != nil {
			return nil, fmt.Errorf("time_range.to must be an RFC3339 timestamp with timezone")
		}
	}
	if !from.Before(to) {
		return nil, fmt.Errorf("time_range.from must precede time_range.to")
	}
	return &TimeRange{From: from.UTC().Format(time.RFC3339Nano), To: to.UTC().Format(time.RFC3339Nano)}, nil
}

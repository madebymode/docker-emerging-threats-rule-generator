package main

import (
	"math/rand/v2"
	"os"
	"strconv"
	"time"
)

// computeNextRun returns the next scheduled update time in local time.
// Default: 03:00 local with up to 60 minutes of jitter to spread load across
// deployments that pull from the same upstream blocklist sources.
func computeNextRun() time.Time {
	hour := envInt("ETR_AT_HOUR", 3, 0, 23)
	jitterMax := envInt("ETR_JITTER_MINUTES", 60, 0, 240)

	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	if jitterMax > 0 {
		next = next.Add(time.Duration(rand.IntN(jitterMax*60)) * time.Second)
	}
	return next
}

func envInt(key string, def, min, max int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		logf("Invalid %s=%q (must be int in [%d,%d]), using default %d\n", key, v, min, max, def)
		return def
	}
	return n
}

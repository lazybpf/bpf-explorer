package web

import (
	"fmt"
	"time"
)

// loadedTime is a program's load time shown two ways: the age, which is what a
// column of these is scanned for - the program loaded a minute ago in a list
// where everything else has been up for days - and the timestamp behind it,
// which is what matches a row against `bpftool prog show`.
type loadedTime struct {
	Ago string
	At  string
}

// loadedAt renders the loaded_at the agent dated on the node. Nil - so a
// template can fall through with {{with}} - when the node sent none: the kernel
// has only reported a program's load time since 4.15.
func loadedAt(unixNano int64) *loadedTime {
	if unixNano <= 0 {
		return nil
	}
	t := time.Unix(0, unixNano)
	// The age is this process subtracting its own clock from the node's, so a
	// node whose clock runs ahead of the UI's shows everything slightly younger.
	// Seconds of skew do not change what the column is read for, and the
	// timestamp beside it is the node's own answer.
	return &loadedTime{Ago: age(time.Since(t)), At: t.Format("2006-01-02T15:04:05-0700")}
}

// age is a duration at one unit of resolution - the largest that is not zero.
// A program's age is read for its order of magnitude ("seconds" vs "days"), and
// a table of "3h17m42s" is a table nobody scans.
func age(d time.Duration) string {
	// Negative is clock skew, not a program loaded in the future: the node dated
	// the load and this process is subtracting its own now. Floor it rather than
	// print "-2s".
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	}
}

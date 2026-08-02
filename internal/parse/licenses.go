package parse

import (
	"strings"
	"time"

	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// licenseDateLayout matches transcript dates like "November 21, 2026".
const licenseDateLayout = "January 2, 2006"

// ParseLicenses extracts the license inventory from a TSF CLI transcript
// (the output of the license-info diagnostic command). Returns nil when the
// transcript has no license section.
func ParseLicenses(transcript string) []model.License {
	idx := strings.Index(transcript, "request license info")
	if idx < 0 {
		return nil
	}
	section := transcript[idx:]
	// The section ends at the next transcribed command ("\n> ").
	if end := strings.Index(section, "\n> "); end > 0 {
		section = section[:end]
	}

	var out []model.License
	var cur *model.License
	flush := func() {
		if cur != nil && cur.Feature != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if line == "License entry:" {
			flush()
			cur = &model.License{}
			continue
		}
		if cur == nil {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "Feature":
			cur.Feature = val
		case "Description":
			cur.Description = val
		case "Expires":
			if strings.EqualFold(val, "never") {
				cur.Never = true
			} else if t, err := time.Parse(licenseDateLayout, val); err == nil {
				cur.Expires = t
			}
		case "Expired?":
			cur.Expired = strings.EqualFold(val, "yes")
		}
	}
	flush()
	return out
}

package parse

import (
	"testing"
	"time"
)

const sampleTranscript = `
> show system info

hostname: TESTFW-01

> request license info

License entry:
Feature: Threat Prevention
Description: Threat Prevention
Serial: 000000000000
Issued: March 31, 2023
Expires: November 21, 2026
Expired?: no

License entry:
Feature: PAN-DB URL Filtering
Description: URL Filtering License
Serial: 000000000000
Issued: July 14, 2021
Expires: March 18, 2024
Expired?: yes

License entry:
Feature: PA-VM
Description: Perpetual capacity license
Serial: 000000000000
Issued: January 1, 2020
Expires: Never
Expired?: no

> show jobs all

nothing here
`

func TestParseLicenses(t *testing.T) {
	lics := ParseLicenses(sampleTranscript)
	if len(lics) != 3 {
		t.Fatalf("parsed %d licenses, want 3", len(lics))
	}
	tp := lics[0]
	if tp.Feature != "Threat Prevention" || tp.Expired || tp.Never {
		t.Errorf("threat prevention parsed wrong: %+v", tp)
	}
	if want := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC); !tp.Expires.Equal(want) {
		t.Errorf("expires = %v, want %v", tp.Expires, want)
	}
	if url := lics[1]; !url.Expired {
		t.Errorf("url filtering should be expired: %+v", url)
	}
	if vm := lics[2]; !vm.Never || vm.Expired {
		t.Errorf("perpetual license parsed wrong: %+v", vm)
	}
}

func TestParseLicensesAbsent(t *testing.T) {
	if got := ParseLicenses("> show system info\n\nhostname: x\n"); got != nil {
		t.Errorf("expected nil for transcript without license section, got %+v", got)
	}
}

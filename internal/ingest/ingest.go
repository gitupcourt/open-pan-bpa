// Package ingest loads a PAN-OS configuration from either a bare XML export or
// a tech support file (.tgz). Archive entries are streamed into memory only —
// nothing from an archive is ever written to disk, so there is no
// extraction-path (zip-slip) surface.
package ingest

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/gitupcourt/open-pan-bpa/internal/xmlnode"
)

// maxConfigBytes caps how much of a config entry we will read into memory,
// as a defense against decompression bombs. Real-world PAN-OS configs are
// single-digit MB; the vendor's own service documents a 100 MB limit.
const maxConfigBytes = 256 << 20 // 256 MiB

// maxArchiveBytes caps the total decompressed bytes consumed while scanning a
// tech support archive, including entries we skip past. Legitimate TSFs
// decompress to low single-digit GiB at most; without this cap a crafted
// gzip bomb could spin the scan indefinitely.
const maxArchiveBytes = 16 << 30 // 16 GiB

// cappedReader errors once more than limit bytes have been read through it.
type cappedReader struct {
	r     io.Reader
	limit int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.limit -= int64(n)
	if c.limit < 0 {
		return n, fmt.Errorf("archive exceeds %d decompressed bytes", int64(maxArchiveBytes))
	}
	return n, err
}

// Config file candidates inside a TSF, in preference order. The merged config
// (hidden dotfile) includes Panorama-pushed content and is preferred when
// present.
var tsfConfigCandidates = []string{
	".merged-running-config.xml",
	"merged-running-config.xml",
	"running-config.xml",
}

// maxTranscriptBytes caps the CLI transcript read from a TSF.
const maxTranscriptBytes = 64 << 20 // 64 MiB

// Source describes where the loaded config came from.
type Source struct {
	Path       string // input file as given
	Kind       string // "xml" or "tsf"
	entryName  string // archive entry used, if Kind == "tsf"
	transcript string // CLI transcript contents, if present in the TSF
}

// EntryName reports which archive entry supplied the config ("" for bare XML).
func (s Source) EntryName() string { return s.entryName }

// Transcript returns the TSF's CLI command transcript ("" for bare XML or
// when the TSF carries none). It holds diagnostic command output — license
// state, versions — that the config XML does not.
func (s Source) Transcript() string { return s.transcript }

// Load reads the input file and returns the parsed XML root of the
// configuration document.
func Load(inputPath string) (*xmlnode.Node, Source, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return nil, Source{}, err
	}
	defer f.Close()

	lower := strings.ToLower(inputPath)
	if strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".gz") {
		return loadTSF(f, inputPath)
	}

	root, err := xmlnode.Parse(io.LimitReader(f, maxConfigBytes))
	if err != nil {
		return nil, Source{}, fmt.Errorf("parsing %s: %w", inputPath, err)
	}
	if root.Name != "config" {
		return nil, Source{}, fmt.Errorf("%s: root element is <%s>, expected <config>", inputPath, root.Name)
	}
	return root, Source{Path: inputPath, Kind: "xml"}, nil
}

// loadTSF scans a tech support tarball for the best config candidate.
func loadTSF(f *os.File, inputPath string) (*xmlnode.Node, Source, error) {
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, Source{}, fmt.Errorf("%s: not a gzip archive: %w", inputPath, err)
	}
	defer gz.Close()

	// Rank of the best candidate seen so far; lower index = better.
	best := len(tsfConfigCandidates)
	var bestData []byte
	var bestName string
	var transcript []byte

	tr := tar.NewReader(&cappedReader{r: gz, limit: maxArchiveBytes})
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, Source{}, fmt.Errorf("%s: reading archive: %w", inputPath, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := path.Base(hdr.Name)

		// CLI transcript: tmp/cli/techsupport_<host>_<ts>.txt — feeds checks
		// that need device state absent from the config (licenses, versions).
		if transcript == nil && strings.Contains(hdr.Name, "/cli/") &&
			strings.HasPrefix(base, "techsupport") && strings.HasSuffix(base, ".txt") {
			data, err := io.ReadAll(io.LimitReader(tr, maxTranscriptBytes))
			if err == nil {
				transcript = data
			}
			continue
		}

		rank := candidateRank(base)
		if rank < 0 || rank >= best {
			continue
		}
		// Only accept config files from the saved-configs directory to avoid
		// picking up stray same-named files elsewhere in the archive.
		if !strings.Contains(hdr.Name, "saved-configs") {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxConfigBytes+1))
		if err != nil {
			return nil, Source{}, fmt.Errorf("%s: reading %s: %w", inputPath, hdr.Name, err)
		}
		if len(data) > maxConfigBytes {
			return nil, Source{}, fmt.Errorf("%s: %s exceeds %d byte limit", inputPath, hdr.Name, maxConfigBytes)
		}
		best, bestData, bestName = rank, data, hdr.Name
		if best == 0 && transcript != nil {
			break // found both the top-preference config and the transcript
		}
	}

	if bestData == nil {
		return nil, Source{}, fmt.Errorf("%s: no running-config.xml found under saved-configs/ — is this a PAN-OS tech support file?", inputPath)
	}
	root, err := xmlnode.Parse(strings.NewReader(string(bestData)))
	if err != nil {
		return nil, Source{}, fmt.Errorf("%s: parsing %s: %w", inputPath, bestName, err)
	}
	return root, Source{Path: inputPath, Kind: "tsf", entryName: bestName, transcript: string(transcript)}, nil
}

func candidateRank(base string) int {
	for i, c := range tsfConfigCandidates {
		if base == c {
			return i
		}
	}
	return -1
}

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

// Config file candidates inside a TSF, in preference order. The merged config
// (hidden dotfile) includes Panorama-pushed content and is preferred when
// present.
var tsfConfigCandidates = []string{
	".merged-running-config.xml",
	"merged-running-config.xml",
	"running-config.xml",
}

// Source describes where the loaded config came from.
type Source struct {
	Path      string // input file as given
	Kind      string // "xml" or "tsf"
	entryName string // archive entry used, if Kind == "tsf"
}

// EntryName reports which archive entry supplied the config ("" for bare XML).
func (s Source) EntryName() string { return s.entryName }

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

	tr := tar.NewReader(gz)
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
		if best == 0 {
			break // already found the top-preference file
		}
	}

	if bestData == nil {
		return nil, Source{}, fmt.Errorf("%s: no running-config.xml found under saved-configs/ — is this a PAN-OS tech support file?", inputPath)
	}
	root, err := xmlnode.Parse(strings.NewReader(string(bestData)))
	if err != nil {
		return nil, Source{}, fmt.Errorf("%s: parsing %s: %w", inputPath, bestName, err)
	}
	return root, Source{Path: inputPath, Kind: "tsf", entryName: bestName}, nil
}

func candidateRank(base string) int {
	for i, c := range tsfConfigCandidates {
		if base == c {
			return i
		}
	}
	return -1
}

// Command bpa is the open-pan-bpa CLI.
//
// Usage:
//
//	bpa scan <config.xml | techsupport.tgz> [--out DIR] [--format json,html,csv] [--packs DIR]
//	bpa version
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitupcourt/open-pan-bpa/internal/checks"
	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/ingest"
	"github.com/gitupcourt/open-pan-bpa/internal/parse"
	"github.com/gitupcourt/open-pan-bpa/internal/report"
	"github.com/gitupcourt/open-pan-bpa/packs"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println("open-pan-bpa", version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `open-pan-bpa — offline Best Practice Assessment for PAN-OS configurations
(not an official Palo Alto Networks product)

usage:
  bpa scan <config.xml | techsupport.tgz> [flags]
  bpa version

flags for scan:
  --out DIR        output directory (default: current directory)
  --format LIST    comma-separated: json,html,csv (default: json,html)
  --packs DIR      load check packs from DIR instead of the built-in packs`)
}

func runScan(args []string) error {
	fset := flag.NewFlagSet("scan", flag.ExitOnError)
	outDir := fset.String("out", ".", "output directory")
	formats := fset.String("format", "json,html", "output formats: json,html,csv")
	packsDir := fset.String("packs", "", "external check pack directory")
	if err := fset.Parse(args); err != nil {
		return err
	}
	// The flag package stops at the first positional argument; re-parse the
	// tail so "bpa scan input.tgz --out dir" works as naturally as flags-first.
	rest := fset.Args()
	if len(rest) == 0 {
		return fmt.Errorf("scan requires an input file")
	}
	input := rest[0]
	if len(rest) > 1 {
		if err := fset.Parse(rest[1:]); err != nil {
			return err
		}
		if fset.NArg() > 0 {
			return fmt.Errorf("scan accepts exactly one input file (got %q and %q)", input, fset.Arg(0))
		}
	}

	root, src, err := ingest.Load(input)
	if err != nil {
		return err
	}
	cfg, err := parse.Build(root)
	if err != nil {
		return err
	}
	if ts := src.Transcript(); ts != "" {
		cfg.LicenseInfoAvailable = true
		cfg.Licenses = parse.ParseLicenses(ts)
	}

	var packFS fs.FS = packs.FS
	if *packsDir != "" {
		packFS = os.DirFS(*packsDir)
	}
	loaded, err := engine.LoadPacks(packFS)
	if err != nil {
		return err
	}

	rep, err := engine.Run(cfg, loaded, checks.Registry(), version)
	if err != nil {
		return err
	}
	rep.InputPath = filepath.Base(src.Path)
	rep.InputKind = src.Kind

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	base := "bpa-" + sanitize(cfg.Hostname)
	for _, f := range strings.Split(*formats, ",") {
		var path string
		var write func(*os.File) error
		switch strings.TrimSpace(f) {
		case "json":
			path = filepath.Join(*outDir, base+".json")
			write = func(fh *os.File) error { return report.WriteJSON(fh, rep) }
		case "html":
			path = filepath.Join(*outDir, base+".html")
			write = func(fh *os.File) error { return report.WriteHTML(fh, rep) }
		case "csv":
			path = filepath.Join(*outDir, base+".csv")
			write = func(fh *os.File) error { return report.WriteCSV(fh, rep) }
		case "":
			continue
		default:
			return fmt.Errorf("unknown format %q", f)
		}
		fh, err := os.Create(path)
		if err != nil {
			return err
		}
		if err := write(fh); err != nil {
			fh.Close()
			return err
		}
		if err := fh.Close(); err != nil {
			return err
		}
		fmt.Println("wrote", path)
	}

	s := rep.Summary
	fmt.Printf("%s: %d checks over %d objects — %d pass / %d fail / %d notes\n",
		cfg.Hostname, s.Checks, s.Objects, s.Pass, s.Fail, s.Notes)
	return nil
}

func sanitize(s string) string {
	if s == "" {
		return "report"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, s)
}

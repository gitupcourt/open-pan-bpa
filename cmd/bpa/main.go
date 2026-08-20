// Command bpa is the open-pan-bpa CLI.
//
// Usage:
//
//	bpa scan <config.xml | techsupport.tgz> [--out DIR] [--format json,html,csv] [--packs DIR]
//	bpa render <report.json> [--out DIR] [--format html,csv]
//	bpa catalog
//	bpa version
package main

import (
	"encoding/json"
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
	case "render":
		if err := runRender(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "catalog":
		if err := runCatalog(os.Args[2:]); err != nil {
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
  bpa render <report.json> [flags]
  bpa catalog [--packs DIR]
  bpa version

flags for scan:
  --out DIR        output directory (default: current directory)
  --format LIST    comma-separated: json,html,csv (default: json,html)
  --packs DIR      load check packs from DIR instead of the built-in packs

render re-emits an existing report JSON as HTML/CSV (default: html,csv) —
presentation is versioned with this binary, so external producers of the
report schema get identical output. catalog prints the built-in check
catalog (slugs, titles, severities, sections, pan_bpa_ids) as JSON.`)
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
	cfg, err := parse.BuildAuto(root)
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

	if err := writeOutputs(rep, *outDir, *formats); err != nil {
		return err
	}

	s := rep.Summary
	fmt.Printf("%s: %d checks over %d objects — %d pass / %d fail / %d notes\n",
		cfg.Hostname, s.Checks, s.Objects, s.Pass, s.Fail, s.Notes)
	return nil
}

// writeOutputs emits rep in each requested format under outDir.
func writeOutputs(rep *engine.Report, outDir, formats string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	base := "bpa-" + sanitize(rep.Hostname)
	for _, f := range strings.Split(formats, ",") {
		var path string
		var write func(*os.File) error
		switch strings.TrimSpace(f) {
		case "json":
			path = filepath.Join(outDir, base+".json")
			write = func(fh *os.File) error { return report.WriteJSON(fh, rep) }
		case "html":
			path = filepath.Join(outDir, base+".html")
			write = func(fh *os.File) error { return report.WriteHTML(fh, rep) }
		case "csv":
			path = filepath.Join(outDir, base+".csv")
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
	return nil
}

// runRender re-emits an existing report JSON as HTML/CSV. The report may come
// from this tool or from any producer of the same schema; presentation then
// stays defined in exactly one place.
func runRender(args []string) error {
	fset := flag.NewFlagSet("render", flag.ExitOnError)
	outDir := fset.String("out", ".", "output directory")
	formats := fset.String("format", "html,csv", "output formats: json,html,csv")
	if err := fset.Parse(args); err != nil {
		return err
	}
	rest := fset.Args()
	if len(rest) == 0 {
		return fmt.Errorf("render requires a report JSON file")
	}
	input := rest[0]
	if len(rest) > 1 {
		if err := fset.Parse(rest[1:]); err != nil {
			return err
		}
		if fset.NArg() > 0 {
			return fmt.Errorf("render accepts exactly one report file (got %q and %q)", input, fset.Arg(0))
		}
	}

	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var rep engine.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return fmt.Errorf("parsing %s: %w", input, err)
	}
	if rep.SchemaVersion == "" {
		return fmt.Errorf("%s: no schema_version — not an open-pan-bpa report", input)
	}
	if major := strings.SplitN(rep.SchemaVersion, ".", 2)[0]; major != strings.SplitN(engine.SchemaVersion, ".", 2)[0] {
		return fmt.Errorf("%s: schema_version %s is incompatible with this binary's %s", input, rep.SchemaVersion, engine.SchemaVersion)
	}
	if err := writeOutputs(&rep, *outDir, *formats); err != nil {
		return err
	}
	s := rep.Summary
	fmt.Printf("%s: %d checks over %d objects — %d pass / %d fail / %d notes\n",
		rep.Hostname, s.Checks, s.Objects, s.Pass, s.Fail, s.Notes)
	return nil
}

// runCatalog prints the check catalog as JSON so external tools can map
// against slugs, severities, sections, and pan_bpa_ids without duplicating
// pack content.
func runCatalog(args []string) error {
	fset := flag.NewFlagSet("catalog", flag.ExitOnError)
	packsDir := fset.String("packs", "", "external check pack directory")
	if err := fset.Parse(args); err != nil {
		return err
	}
	var packFS fs.FS = packs.FS
	if *packsDir != "" {
		packFS = os.DirFS(*packsDir)
	}
	loaded, err := engine.LoadPacks(packFS)
	if err != nil {
		return err
	}
	out := struct {
		SchemaVersion string        `json:"schema_version"`
		ToolVersion   string        `json:"tool_version"`
		Packs         []engine.Pack `json:"packs"`
	}{engine.SchemaVersion, version, loaded}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
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

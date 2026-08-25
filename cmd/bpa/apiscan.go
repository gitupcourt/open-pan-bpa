package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/ingest"
	"github.com/gitupcourt/open-pan-bpa/internal/posture"
	"github.com/gitupcourt/open-pan-bpa/internal/xmlnode"
	"github.com/gitupcourt/open-pan-bpa/packs"
)

// runAPIScan is the ONLY network-capable path in this binary — the explicit,
// deliberate exception to the zero-network-I/O rule. `bpa scan` remains
// absolutely offline; this subcommand exists for operators who want the
// vendor's hosted engine's verdicts with this tool's output formats.
func runAPIScan(args []string) error {
	fset := flag.NewFlagSet("api-scan", flag.ExitOnError)
	outDir := fset.String("out", ".", "output directory")
	formats := fset.String("format", "json,html", "output formats: json,html,csv")
	packsDir := fset.String("packs", "", "external check pack directory (for slug mapping)")
	hostname := fset.String("hostname", "", "hostname for the report (auto-detected from config)")
	keepAPIJSON := fset.Bool("keep-api-json", false, "also write the raw API report JSON")
	noCorrections := fset.Bool("no-corrections", false, "skip scope/disabled/predefined verdict corrections")
	deleteAfter := fset.Bool("delete-after-processing", false, "ask the service to delete the uploaded config after processing")
	gzipUpload := fset.Bool("gzip-upload", false, "actually gzip the upload body (the backend usually rejects this; raw upload is the working default)")
	timeout := fset.Duration("timeout", 15*time.Minute, "overall API timeout")
	interval := fset.Duration("interval", 10*time.Second, "poll interval")
	if err := fset.Parse(args); err != nil {
		return err
	}
	rest := fset.Args()
	if len(rest) == 0 {
		return fmt.Errorf("api-scan requires an input file (config.xml or techsupport archive)")
	}
	input := rest[0]
	if len(rest) > 1 {
		if err := fset.Parse(rest[1:]); err != nil {
			return err
		}
		if fset.NArg() > 0 {
			return fmt.Errorf("api-scan accepts exactly one input file (got %q and %q)", input, fset.Arg(0))
		}
	}

	creds := posture.Credentials{
		ClientID:     os.Getenv("PANW_CLIENT_ID"),
		ClientSecret: os.Getenv("PANW_CLIENT_SECRET"),
		TSGID:        os.Getenv("PANW_TSG_ID"),
	}
	if creds.ClientID == "" || creds.ClientSecret == "" || creds.TSGID == "" {
		return fmt.Errorf("set PANW_CLIENT_ID, PANW_CLIENT_SECRET, and PANW_TSG_ID (credentials are env-only by design; see https://pan.dev/sase/docs/service-accounts/)")
	}

	configXML, src, err := ingest.LoadRaw(input)
	if err != nil {
		return err
	}
	host := *hostname
	if host == "" {
		host = rawHostname(configXML)
	}

	fmt.Fprintf(os.Stderr, "NOTE: api-scan UPLOADS this configuration to Palo Alto Networks' hosted service\n")
	fmt.Fprintf(os.Stderr, "      (%d KB from %s). For a fully offline assessment use `bpa scan`.\n", len(configXML)/1024, filepath.Base(src.Path))
	if !*deleteAfter {
		fmt.Fprintln(os.Stderr, "      Tip: --delete-after-processing asks the service to delete the config once the report is generated.")
	}

	token, err := posture.Token(creds)
	if err != nil {
		return err
	}
	apiJSON, err := posture.Fetch(token, configXML, posture.Options{
		DeleteAfterProcessing: *deleteAfter,
		GzipUpload:            *gzipUpload,
		Timeout:               *timeout,
		Interval:              *interval,
		Log: func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, "      "+format+"\n", a...)
		},
	})
	if err != nil {
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
	rep, err := posture.Convert(apiJSON, loaded, host, filepath.Base(src.Path), version, !*noCorrections,
		func(format string, a ...any) { fmt.Fprintf(os.Stderr, "      "+format+"\n", a...) })
	if err != nil {
		return err
	}

	if *keepAPIJSON {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return err
		}
		raw := filepath.Join(*outDir, "api-raw-"+sanitize(rep.Hostname)+".json")
		if err := os.WriteFile(raw, apiJSON, 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", raw)
	}
	if err := writeOutputs(rep, *outDir, *formats); err != nil {
		return err
	}
	s := rep.Summary
	fmt.Printf("%s: %d checks over %d objects — %d pass / %d fail / %d notes\n",
		rep.Hostname, s.Checks, s.Objects, s.Pass, s.Fail, s.Notes)
	return nil
}

// rawHostname pulls deviceconfig/system/hostname without a full model build.
func rawHostname(configXML []byte) string {
	root, err := xmlnode.Parse(strings.NewReader(string(configXML)))
	if err != nil {
		return ""
	}
	dev := root.First("devices", "entry")
	if dev == nil {
		return ""
	}
	return dev.ChildText("deviceconfig", "system", "hostname")
}

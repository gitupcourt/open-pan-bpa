package ingest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTar returns an uncompressed tar archive holding a minimal config.
func buildTar(t *testing.T) []byte {
	t.Helper()
	config := []byte(`<config version="11.1.0"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>`)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: "./opt/pancfg/mgmt/saved-configs/running-config.xml",
		Mode: 0o644, Size: int64(len(config)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(config); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadTSFGzipped(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(buildTar(t)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	root, src, err := Load(writeTemp(t, "device.tgz", buf.Bytes()))
	if err != nil {
		t.Fatalf("gzipped TSF: %v", err)
	}
	if root.Name != "config" || src.Kind != "tsf" {
		t.Fatalf("got root %q kind %q", root.Name, src.Kind)
	}
}

// A .tgz whose gzip layer was stripped in transit (browser/proxy
// Content-Encoding handling) must still load as a plain tar.
func TestLoadTSFPlainTarNamedTgz(t *testing.T) {
	root, src, err := Load(writeTemp(t, "device.tgz", buildTar(t)))
	if err != nil {
		t.Fatalf("plain tar named .tgz: %v", err)
	}
	if root.Name != "config" || src.Kind != "tsf" {
		t.Fatalf("got root %q kind %q", root.Name, src.Kind)
	}
}

func TestLoadTSFPlainTarExtension(t *testing.T) {
	if _, _, err := Load(writeTemp(t, "device.tar", buildTar(t))); err != nil {
		t.Fatalf(".tar input: %v", err)
	}
}

func TestLoadTSFNeitherFormat(t *testing.T) {
	_, _, err := Load(writeTemp(t, "device.tgz", []byte("this is not an archive")))
	if err == nil {
		t.Fatal("expected error for non-archive input")
	}
	if !strings.Contains(err.Error(), "neither a gzip archive nor a tar archive") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// Package posture drives Palo Alto Networks' hosted BPA (posture) API and
// converts its report into the engine's report schema.
//
// NETWORK I/O NOTICE: this package is the deliberate, explicit exception to
// the project's zero-network-I/O rule. It is reachable ONLY through the
// `bpa api-scan` subcommand — never through `bpa scan`, whose offline
// guarantee is absolute. Uploading a configuration to the vendor service is
// the entire point of this mode, and the CLI says so loudly before doing it.
//
// The flow and its quirks mirror the field-proven standalone client
// (gitupcourt/pan-api-bpa). Do not "fix" these behaviors:
//   - The config is uploaded RAW with a Content-Encoding: gzip header; the
//     backend reads the object raw and fails on genuinely gzipped bytes.
//   - Content-Type tries "plain/text" (documented, sic) then "text/plain";
//     the presigned URL signs the header value.
//   - On COMPLETED, result.report_url is often empty; the report lands in
//     result.custom_check_url. Every http(s) URL in result is tried.
//
// API documentation:
//
//	https://pan.dev/scm/api/config/posture-management/introduction-posture/
//	https://pan.dev/sase/docs/service-accounts/
package posture

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	authURL     = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
	postureBase = "https://api.strata.paloaltonetworks.com"
)

// Credentials for the SCM service account (env-only at the CLI layer).
type Credentials struct {
	ClientID     string
	ClientSecret string
	TSGID        string
}

// Options controls a fetch.
type Options struct {
	DeleteAfterProcessing bool
	GzipUpload            bool // escape hatch; the raw default is what works
	Timeout               time.Duration
	Interval              time.Duration
	Log                   func(format string, args ...any)
}

func (o *Options) logf(format string, args ...any) {
	if o.Log != nil {
		o.Log(format, args...)
	}
}

var httpClient = &http.Client{Timeout: 10 * time.Minute}

// Token exchanges service-account credentials for an OAuth2 access token.
func Token(c Credentials) (string, error) {
	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"tsg_id:" + c.TSGID},
	}
	req, err := http.NewRequest("POST", authURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("authenticating: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("authentication failed (HTTP %d): %s — check PANW_CLIENT_ID/SECRET/TSG_ID", resp.StatusCode, trunc(body, 500))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("no access_token in auth response: %s", trunc(body, 500))
	}
	return tok.AccessToken, nil
}

// Fetch uploads configXML, polls to completion, and returns the raw API
// report JSON.
func Fetch(token string, configXML []byte, opts Options) ([]byte, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Minute
	}
	if opts.Interval == 0 {
		opts.Interval = 10 * time.Second
	}

	opts.logf("initiating config upload (posture API)")
	initBody, _ := json.Marshal(map[string]bool{"delete_after_processing": opts.DeleteAfterProcessing})
	req, _ := http.NewRequest("POST", postureBase+"/posture/checks/v1/reports/config-file-upload", strings.NewReader(string(initBody)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("initiating upload: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limited: maximum of 5 active jobs reached; retry later")
	}
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("upload initiation failed (HTTP %d): %s — verify the service account has an SCM role (Essentials or Pro) on this TSG", resp.StatusCode, trunc(body, 800))
	}
	var initResp struct {
		TaskID    string `json:"task_id"`
		UploadURL string `json:"upload_url"`
	}
	if err := json.Unmarshal(body, &initResp); err != nil || initResp.TaskID == "" || initResp.UploadURL == "" {
		return nil, fmt.Errorf("unexpected initiation response: %s", trunc(body, 800))
	}

	payload := configXML
	if opts.GzipUpload {
		payload = gzipBytes(configXML)
		opts.logf("uploading gzipped config (%d KB) — note: the backend usually rejects genuinely gzipped bytes", len(payload)/1024)
	} else {
		opts.logf("uploading RAW config (%d KB) with gzip header (matching the documented, working behavior)", len(payload)/1024)
	}
	uploaded := false
	for i, ctype := range []string{"plain/text", "text/plain"} {
		req, _ := http.NewRequest("PUT", initResp.UploadURL, strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", ctype)
		req.Header.Set("Content-Encoding", "gzip")
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("uploading config: %w", err)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			uploaded = true
			break
		}
		if strings.Contains(string(b), "SignatureDoesNotMatch") && i == 0 {
			opts.logf("signature mismatch with Content-Type %q; retrying with \"text/plain\"", ctype)
			continue
		}
		return nil, fmt.Errorf("config upload failed (HTTP %d): %s", resp.StatusCode, trunc(b, 800))
	}
	if !uploaded {
		return nil, fmt.Errorf("config upload failed with both content types")
	}

	opts.logf("polling task %s (timeout %s)", initResp.TaskID, opts.Timeout)
	deadline := time.Now().Add(opts.Timeout)
	var lastStatus string
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", postureBase+"/posture/checks/v1/reports/"+url.PathEscape(initResp.TaskID)+"/bpa-result", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("polling: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			var poll struct {
				Status  string         `json:"status"`
				Message string         `json:"message"`
				Result  map[string]any `json:"result"`
			}
			if err := json.Unmarshal(body, &poll); err != nil {
				return nil, fmt.Errorf("parsing poll response: %w", err)
			}
			tag := poll.Status
			if poll.Message != "" {
				tag += " — " + poll.Message
			}
			if tag != lastStatus {
				opts.logf("%s", tag)
				lastStatus = tag
			}
			switch poll.Status {
			case "COMPLETED":
				return downloadReport(poll.Result, opts)
			case "FAILED":
				return nil, fmt.Errorf("processing failed: %s\n%s", poll.Message, trunc(body, 1500))
			}
		} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
			// Token lifetime (~15 min) can be shorter than a long poll;
			// spinning here would silently burn the whole timeout.
			return nil, fmt.Errorf("token rejected while polling (HTTP %d) — it may have expired; rerun to re-authenticate", resp.StatusCode)
		} else if resp.StatusCode != 404 {
			opts.logf("transient HTTP %d, retrying", resp.StatusCode)
		}
		time.Sleep(opts.Interval)
	}
	return nil, fmt.Errorf("timed out after %s waiting for task %s", opts.Timeout, initResp.TaskID)
}

// downloadReport fetches the report from the completed result. report_url is
// preferred but often empty; every http(s) URL in the result is tried.
func downloadReport(result map[string]any, opts Options) ([]byte, error) {
	ordered := []string{"report_url", "custom_check_url"}
	for k := range result {
		if k != "report_url" && k != "custom_check_url" {
			ordered = append(ordered, k)
		}
	}
	for _, key := range ordered {
		u, ok := result[key].(string)
		// https only: the derived report must never travel cleartext, even
		// if the service were ever to hand back an http:// URL.
		if !ok || !strings.HasPrefix(u, "https://") {
			continue
		}
		resp, err := httpClient.Get(u)
		if err != nil {
			opts.logf("download of %s failed: %v; trying next", key, err)
			continue
		}
		// The cap is deliberately far above the poll/auth limits: real
		// fleet-scale (Panorama) reports run ~100 MB of JSON.
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			opts.logf("download of %s failed (HTTP %d); trying next", key, resp.StatusCode)
			continue
		}
		opts.logf("downloaded %s (%d KB)", key, len(body)/1024)
		return body, nil
	}
	return nil, fmt.Errorf("completed, but no downloadable report URL in result (signed URLs expire in ~30 minutes; rerun)")
}

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(data)
	gz.Close()
	return buf.Bytes()
}

func trunc(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

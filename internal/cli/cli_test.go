package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func runCmd(t *testing.T, rootName string, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	out, _ := io.ReadAll(buf)
	return string(out), err
}

func TestVersionCommand(t *testing.T) {
	out, err := runCmd(t, "sentinel", "version")
	if err != nil {
		t.Fatalf("version failed: %v", err)
	}
	if !strings.HasPrefix(out, "sentinel ") {
		t.Fatalf("unexpected version output: %q", out)
	}
}

func TestHealthcheckOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	out, err := runCmd(t, "sentinel", "healthcheck", "--url", srv.URL+"/healthz")
	if err != nil {
		t.Fatalf("healthcheck failed: %v", err)
	}
	if strings.TrimSpace(out) != "ok" {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestHealthcheckServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	_, err := runCmd(t, "sentinel", "healthcheck", "--url", srv.URL+"/healthz")
	if err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("expected status error, got %v", err)
	}
}

func TestHealthcheckConnectionError(t *testing.T) {
	_, err := runCmd(t, "sentinel", "healthcheck", "--url", "http://127.0.0.1:1/healthz", "--timeout", "200ms")
	if err == nil {
		t.Fatal("expected connection error")
	}
}

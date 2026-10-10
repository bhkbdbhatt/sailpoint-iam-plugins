package api_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestSystemEndpoints(t *testing.T) {
	e := setup(t)

	cases := []struct {
		path string
		code int
	}{
		{"/healthz", http.StatusOK},
		{"/readyz", http.StatusOK},
		{"/metrics", http.StatusOK},
		{"/openapi.yaml", http.StatusOK},
		{"/docs", http.StatusOK},
	}
	for _, c := range cases {
		status, _ := do(t, http.MethodGet, e.srv.URL+c.path, "", nil)
		if status != c.code {
			t.Fatalf("%s: want %d, got %d", c.path, c.code, status)
		}
	}
}

func TestOpenAPISpecServed(t *testing.T) {
	e := setup(t)
	status, body := do(t, http.MethodGet, e.srv.URL+"/openapi.yaml", "", nil)
	if status != http.StatusOK {
		t.Fatalf("openapi status %d", status)
	}
	if !strings.Contains(string(body), "openapi: 3.1.0") {
		t.Fatalf("spec missing version header: %s", body[:64])
	}
	if !strings.Contains(string(body), "/v1/identities") {
		t.Fatal("spec missing /v1/identities path")
	}
}

func TestDocsServed(t *testing.T) {
	e := setup(t)
	status, body := do(t, http.MethodGet, e.srv.URL+"/docs", "", nil)
	if status != http.StatusOK {
		t.Fatalf("docs status %d", status)
	}
	if !strings.Contains(string(body), "SwaggerUIBundle") {
		t.Fatal("docs page missing swagger bundle")
	}
}

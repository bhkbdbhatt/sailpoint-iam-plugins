package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sentinel-iam/sentinel/internal/api"
	"github.com/sentinel-iam/sentinel/internal/auth"
	"github.com/sentinel-iam/sentinel/internal/bootstrap"
	"github.com/sentinel-iam/sentinel/internal/connector"
	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/secrets"
	"github.com/sentinel-iam/sentinel/internal/store"
)

type env struct {
	srv   *httptest.Server
	store store.Store
}

func setup(t *testing.T) *env {
	t.Helper()
	st := store.NewMemory()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	jwtm := auth.NewJWTManagerFromKey(key, "test", time.Hour)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("master key: %v", err)
	}
	box, err := secrets.NewFromKey(masterKey)
	if err != nil {
		t.Fatalf("box: %v", err)
	}
	if _, err := bootstrap.EnsureOwner(context.Background(), st, "Acme", "acme", "owner@example.com", "Owner", "supersecret123"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	runner := connector.NewRunner(st, connector.Default(), box, time.Minute, nil)
	srv := httptest.NewServer(api.New(st, jwtm, box, runner, nil).Handler())
	t.Cleanup(srv.Close)
	return &env{srv: srv, store: st}
}

func do(t *testing.T, method, url, token string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func login(t *testing.T, e *env, email, password string) string {
	t.Helper()
	status, body := do(t, http.MethodPost, e.srv.URL+"/v1/auth/login", "", map[string]string{"email": email, "password": password})
	if status != http.StatusOK {
		t.Fatalf("login status %d: %s", status, body)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("login decode: %v", err)
	}
	return out.Token
}

func TestUnauthenticated(t *testing.T) {
	e := setup(t)
	status, _ := do(t, http.MethodGet, e.srv.URL+"/v1/identities", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestEndToEndFlow(t *testing.T) {
	e := setup(t)
	token := login(t, e, "owner@example.com", "supersecret123")

	status, body := do(t, http.MethodPost, e.srv.URL+"/v1/identities", token, map[string]any{
		"type":          "human",
		"name":          "Jane Doe",
		"source_system": "manual",
		"external_id":   "jane-1",
		"risk_score":    40,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity status %d: %s", status, body)
	}

	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/identities?types=human", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list identities status %d: %s", status, body)
	}
	var list struct {
		Total int              `json:"total"`
		Data  []model.Identity `json:"data"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Total != 1 || len(list.Data) != 1 {
		t.Fatalf("expected 1 identity, got total=%d len=%d", list.Total, len(list.Data))
	}

	status, body = do(t, http.MethodPost, e.srv.URL+"/v1/connectors", token, map[string]any{
		"key":     "simulated",
		"name":    "sim",
		"enabled": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create connector status %d: %s", status, body)
	}
	var createdConnector model.ConnectorConfig
	if err := json.Unmarshal(body, &createdConnector); err != nil {
		t.Fatalf("decode connector: %v", err)
	}

	status, body = do(t, http.MethodPost, e.srv.URL+"/v1/connectors/"+createdConnector.ID+"/run", token, nil)
	if status != http.StatusOK {
		t.Fatalf("run connector status %d: %s", status, body)
	}
	var run model.ConnectorRun
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if run.Status != model.ConnectorStatusSucceeded {
		t.Fatalf("expected succeeded run, got %s: %s", run.Status, run.Error)
	}
	if run.IdentitiesFound == 0 || run.ResourcesFound == 0 || run.GrantsFound == 0 {
		t.Fatalf("expected discovered data, got %+v", run)
	}

	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/stats/overview", token, nil)
	if status != http.StatusOK {
		t.Fatalf("overview status %d: %s", status, body)
	}
	var ov model.Overview
	if err := json.Unmarshal(body, &ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if ov.TotalIdentities == 0 || ov.TotalCredentials == 0 || ov.TotalGrants == 0 {
		t.Fatalf("unexpected overview: %+v", ov)
	}
}

func TestViewerForbidden(t *testing.T) {
	e := setup(t)
	ownerToken := login(t, e, "owner@example.com", "supersecret123")

	status, body := do(t, http.MethodPost, e.srv.URL+"/v1/users", ownerToken, map[string]any{
		"email":    "viewer@example.com",
		"name":     "Viewer",
		"password": "supersecret123",
		"role":     "viewer",
	})
	if status != http.StatusCreated {
		t.Fatalf("create viewer status %d: %s", status, body)
	}

	viewerToken := login(t, e, "viewer@example.com", "supersecret123")
	status, _ = do(t, http.MethodPost, e.srv.URL+"/v1/identities", viewerToken, map[string]any{
		"type":          "human",
		"name":          "Nope",
		"source_system": "manual",
	})
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer write, got %d", status)
	}
}

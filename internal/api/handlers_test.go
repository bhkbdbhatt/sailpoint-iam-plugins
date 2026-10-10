package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func mustID(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode id: %v (%s)", err, body)
	}
	if out.ID == "" {
		t.Fatalf("no id in response: %s", body)
	}
	return out.ID
}

func TestUsersCRUD(t *testing.T) {
	e := setup(t)
	token := login(t, e, "owner@example.com", "supersecret123")

	// duplicate email -> owner already exists
	status, _ := do(t, http.MethodPost, e.srv.URL+"/v1/users", token, map[string]any{
		"email": "owner@example.com", "name": "Dup", "password": "supersecret123", "role": "viewer",
	})
	if status != http.StatusConflict {
		t.Fatalf("duplicate email: got %d", status)
	}
	// weak password -> 400
	status, _ = do(t, http.MethodPost, e.srv.URL+"/v1/users", token, map[string]any{
		"email": "weak@example.com", "name": "Weak", "password": "admin123", "role": "viewer",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("weak password: got %d", status)
	}
	// invalid JSON body -> 400
	status, _ = do(t, http.MethodPost, e.srv.URL+"/v1/users", token, "not-json")
	if status != http.StatusBadRequest {
		t.Fatalf("bad body: got %d", status)
	}

	status, body := do(t, http.MethodPost, e.srv.URL+"/v1/users", token, map[string]any{
		"email": "dev@example.com", "name": "Dev", "password": "supersecret123", "role": "analyst",
	})
	if status != http.StatusCreated {
		t.Fatalf("create user: %d %s", status, body)
	}
	id := mustID(t, body)

	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/users/"+id, token, nil)
	if status != http.StatusOK {
		t.Fatalf("get user: %d %s", status, body)
	}

	status, body = do(t, http.MethodPut, e.srv.URL+"/v1/users/"+id, token, map[string]any{
		"name": "Dev2", "role": "viewer", "status": "disabled", "password": "newpass123456",
	})
	if status != http.StatusOK {
		t.Fatalf("update user: %d %s", status, body)
	}
	var updated struct {
		Name   string `json:"name"`
		Role   string `json:"role"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Dev2" || updated.Role != "viewer" || updated.Status != "disabled" {
		t.Fatalf("update not applied: %+v", updated)
	}

	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/users?role=viewer&status=disabled", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list users: %d %s", status, body)
	}
	var list struct {
		Total int `json:"total"`
		Data  []struct {
			Email string `json:"email"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || list.Data[0].Email != "dev@example.com" {
		t.Fatalf("list mismatch: %+v", list)
	}

	status, _ = do(t, http.MethodDelete, e.srv.URL+"/v1/users/"+id, token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete user: %d", status)
	}
	status, _ = do(t, http.MethodGet, e.srv.URL+"/v1/users/"+id, token, nil)
	if status != http.StatusNotFound {
		t.Fatalf("get deleted user: %d", status)
	}
	status, _ = do(t, http.MethodGet, e.srv.URL+"/v1/users/nope", token, nil)
	if status != http.StatusNotFound {
		t.Fatalf("get missing user: %d", status)
	}
}

func TestAPIKeysFlow(t *testing.T) {
	e := setup(t)
	token := login(t, e, "owner@example.com", "supersecret123")

	status, body := do(t, http.MethodPost, e.srv.URL+"/v1/apikeys", token, map[string]any{"name": "ci-key", "role": "admin"})
	if status != http.StatusCreated {
		t.Fatalf("create key: %d %s", status, body)
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" || created.ID == "" {
		t.Fatalf("key response missing token/id: %s", body)
	}

	// Use the plaintext key as a bearer substitute via X-API-Key.
	status, _ = do(t, http.MethodGet, e.srv.URL+"/v1/identities", created.Token, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("plaintext token should not pass as bearer: %d", status)
	}

	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/apikeys", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list keys: %d %s", status, body)
	}
	var list struct {
		Total int `json:"total"`
		Data  []struct {
			ID      string `json:"id"`
			Revoked bool   `json:"revoked"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || list.Data[0].ID != created.ID {
		t.Fatalf("list keys mismatch: %+v", list)
	}

	// invalid role -> 400
	status, _ = do(t, http.MethodPost, e.srv.URL+"/v1/apikeys", token, map[string]any{"name": "k", "role": "boss"})
	if status != http.StatusBadRequest {
		t.Fatalf("bad role: %d", status)
	}

	status, body = do(t, http.MethodDelete, e.srv.URL+"/v1/apikeys/"+created.ID, token, nil)
	if status != http.StatusOK {
		t.Fatalf("revoke: %d %s", status, body)
	}
	var revoked struct {
		Revoked bool `json:"revoked"`
	}
	if err := json.Unmarshal(body, &revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked.Revoked {
		t.Fatalf("revoke flag not set: %s", body)
	}
	// Revoking an already revoked key is idempotent.
	status, _ = do(t, http.MethodDelete, e.srv.URL+"/v1/apikeys/"+created.ID, token, nil)
	if status != http.StatusOK {
		t.Fatalf("revoke twice: %d", status)
	}
	// Revoked keys still list, marked revoked.
	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/apikeys?revoked=true", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list revoked: %d", status)
	}
	if !strings.Contains(string(body), `"revoked":true`) {
		t.Fatalf("revoked list did not include the key: %s", body)
	}
}

func TestConnectorsCRUD(t *testing.T) {
	e := setup(t)
	token := login(t, e, "owner@example.com", "supersecret123")

	status, body := do(t, http.MethodPost, e.srv.URL+"/v1/connectors", token, map[string]any{
		"key": "simulated", "name": "sim", "enabled": true, "interval_minutes": 15,
		"secrets": map[string]string{"token": "supersecret-value"},
		"options": map[string]string{"env": "test"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create connector: %d %s", status, body)
	}
	cfgID := mustID(t, body)
	// secrets must be encrypted, not returned.
	if strings.Contains(string(body), "supersecret-value") {
		t.Fatalf("secret leaked in response: %s", body)
	}

	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/connectors/"+cfgID, token, nil)
	if status != http.StatusOK {
		t.Fatalf("get connector: %d %s", status, body)
	}

	status, body = do(t, http.MethodPut, e.srv.URL+"/v1/connectors/"+cfgID, token, map[string]any{"name": "sim2", "enabled": false})
	if status != http.StatusOK {
		t.Fatalf("update connector: %d %s", status, body)
	}
	var updated struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "sim2" || updated.Enabled {
		t.Fatalf("update mismatch: %+v", updated)
	}

	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/connectors?key=simulated&enabled=false", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list connectors: %d", status)
	}
	var list struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 {
		t.Fatalf("connector list: %d", list.Total)
	}

	status, _ = do(t, http.MethodDelete, e.srv.URL+"/v1/connectors/"+cfgID, token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete connector: %d", status)
	}
	status, _ = do(t, http.MethodGet, e.srv.URL+"/v1/connectors/"+cfgID, token, nil)
	if status != http.StatusNotFound {
		t.Fatalf("get deleted connector: %d", status)
	}
	status, _ = do(t, http.MethodGet, e.srv.URL+"/v1/connectors/nope", token, nil)
	if status != http.StatusNotFound {
		t.Fatalf("get missing connector: %d", status)
	}
}

func TestPoliciesCRUD(t *testing.T) {
	e := setup(t)
	token := login(t, e, "owner@example.com", "supersecret123")

	payload := func(name, intent string) map[string]any {
		return map[string]any{
			"name": name, "rules": `{"engine":"credential-age"}`, "engine": "rego",
			"intent_level": intent,
		}
	}
	status, body := do(t, http.MethodPost, e.srv.URL+"/v1/policies", token, payload("pol-a", "role"))
	if status != http.StatusCreated {
		t.Fatalf("create policy: %d %s", status, body)
	}
	pid := mustID(t, body)

	status, _ = do(t, http.MethodPost, e.srv.URL+"/v1/policies", token, payload("pol-b", "bogus"))
	if status != http.StatusBadRequest {
		t.Fatalf("bad intent: %d", status)
	}

	status, _ = do(t, http.MethodGet, e.srv.URL+"/v1/policies/"+pid, token, nil)
	if status != http.StatusOK {
		t.Fatalf("get policy: %d", status)
	}

	status, body = do(t, http.MethodPut, e.srv.URL+"/v1/policies/"+pid, token, map[string]any{
		"name": "pol-a2", "rules": `{"engine":"credential-age"}`, "engine": "rego",
		"intent_level": "org", "status": "active",
	})
	if status != http.StatusOK {
		t.Fatalf("update policy: %d %s", status, body)
	}

	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/policies?intent_level=org&status=active", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list policies: %d", status)
	}
	var list struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 {
		t.Fatalf("policies list: %d", list.Total)
	}

	status, _ = do(t, http.MethodDelete, e.srv.URL+"/v1/policies/"+pid, token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete policy: %d", status)
	}
	status, _ = do(t, http.MethodGet, e.srv.URL+"/v1/policies/"+pid, token, nil)
	if status != http.StatusNotFound {
		t.Fatalf("get deleted policy: %d", status)
	}
}

func TestAlertsCRUD(t *testing.T) {
	e := setup(t)
	token := login(t, e, "owner@example.com", "supersecret123")

	status, body := do(t, http.MethodPost, e.srv.URL+"/v1/alerts", token, map[string]any{
		"identity_id": "i-1", "type": "stale_key", "severity": "high",
		"description": "key is stale", "recommended_action": "rotate",
	})
	if status != http.StatusCreated {
		t.Fatalf("create alert: %d %s", status, body)
	}
	aid := mustID(t, body)

	status, _ = do(t, http.MethodPost, e.srv.URL+"/v1/alerts", token, map[string]any{"type": "x", "severity": "loud"})
	if status != http.StatusBadRequest {
		t.Fatalf("bad severity: %d", status)
	}

	status, _ = do(t, http.MethodGet, e.srv.URL+"/v1/alerts/"+aid, token, nil)
	if status != http.StatusOK {
		t.Fatalf("get alert: %d", status)
	}

	status, body = do(t, http.MethodPatch, e.srv.URL+"/v1/alerts/"+aid, token, map[string]any{"status": "acknowledged", "description": "reviewed"})
	if status != http.StatusOK {
		t.Fatalf("patch alert: %d %s", status, body)
	}
	var patched struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &patched); err != nil {
		t.Fatal(err)
	}
	if patched.Status != "acknowledged" {
		t.Fatalf("patch not applied: %+v", patched)
	}

	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/alerts?severity=high&status=acknowledged&type=stale_key&identity_id=i-1", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list alerts: %d", status)
	}
	var list struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 {
		t.Fatalf("alerts list: %d", list.Total)
	}

	status, _ = do(t, http.MethodDelete, e.srv.URL+"/v1/alerts/"+aid, token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete alert: %d", status)
	}
}

func TestGettersAndCrossReferences(t *testing.T) {
	e := setup(t)
	token := login(t, e, "owner@example.com", "supersecret123")

	// Run simulated connector to populate credentials/grants/resources.
	status, body := do(t, http.MethodPost, e.srv.URL+"/v1/connectors", token, map[string]any{"key": "simulated", "name": "sim", "enabled": true})
	if status != http.StatusCreated {
		t.Fatalf("create connector: %d %s", status, body)
	}
	cfgID := mustID(t, body)
	status, body = do(t, http.MethodPost, e.srv.URL+"/v1/connectors/"+cfgID+"/run", token, nil)
	if status != http.StatusOK {
		t.Fatalf("run: %d %s", status, body)
	}

	getFirst := func(path string) string {
		status, body = do(t, http.MethodGet, e.srv.URL+path, token, nil)
		if status != http.StatusOK {
			t.Fatalf("list %s: %d %s", path, status, body)
		}
		var list struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if len(list.Data) == 0 {
			t.Fatalf("list %s empty", path)
		}
		return list.Data[0].ID
	}

	for _, p := range []string{"/v1/credentials", "/v1/grants", "/v1/resources", "/v1/identities"} {
		id := getFirst(p)
		status, _ := do(t, http.MethodGet, e.srv.URL+p+"/"+id, token, nil)
		if status != http.StatusOK {
			t.Fatalf("get %s/%s: %d", p, id, status)
		}
	}
	// filter correctness
	if _, body = do(t, http.MethodGet, e.srv.URL+"/v1/credentials?expiring_within_days=30", token, nil); status != http.StatusOK {
		t.Fatalf("credentials filter: %d", status)
	}
	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/grants?identity_id=none", token, nil)
	if status != http.StatusOK {
		t.Fatalf("grants filter: %d", status)
	}
	var gl struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &gl); err != nil {
		t.Fatal(err)
	}
	if gl.Total != 0 {
		t.Fatalf("grant identity filter: %d", gl.Total)
	}
	// missing getters
	for _, p := range []string{"/v1/credentials", "/v1/grants", "/v1/resources", "/v1/identities"} {
		status, _ = do(t, http.MethodGet, e.srv.URL+p+"/missing", token, nil)
		if status != http.StatusNotFound {
			t.Fatalf("%s missing: %d", p, status)
		}
	}
}

func TestAuthFlowDetails(t *testing.T) {
	e := setup(t)
	status, body := do(t, http.MethodPost, e.srv.URL+"/v1/auth/login", "", map[string]string{"email": "who@example.com", "password": "wrong-pass-123"})
	if status != http.StatusUnauthorized {
		t.Fatalf("unknown user: %d", status)
	}
	_ = body

	token := login(t, e, "owner@example.com", "supersecret123")
	status, body = do(t, http.MethodGet, e.srv.URL+"/v1/auth/me", token, nil)
	if status != http.StatusOK {
		t.Fatalf("me: %d", status)
	}
	var me struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatal(err)
	}
	if len(me.Permissions) == 0 {
		t.Fatal("me returned no permissions")
	}

	// invalid bearer token
	status, _ = do(t, http.MethodGet, e.srv.URL+"/v1/identities", "not-a-jwt", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("invalid jwt: %d", status)
	}

	// malformed body on login -> 400
	status, _ = do(t, http.MethodPost, e.srv.URL+"/v1/auth/login", "", "not-json")
	if status != http.StatusBadRequest {
		t.Fatalf("login bad body: %d", status)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := setup(t)
	path := e.srv.URL + "/v1/auth/login"
	for i := 0; i < 5; i++ {
		status, _ := do(t, http.MethodPost, path, "", map[string]string{"email": "owner@example.com", "password": "wrong-pass-123"})
		if status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, status)
		}
	}
	// 6th attempt (same IP) exceeds the per-IP limit.
	status, body := do(t, http.MethodPost, path, "", map[string]string{"email": "owner@example.com", "password": "wrong-pass-123"})
	if status != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d (%s)", status, body)
	}
}

func TestIdentityValidationErrors(t *testing.T) {
	e := setup(t)
	token := login(t, e, "owner@example.com", "supersecret123")
	status, _ := do(t, http.MethodPost, e.srv.URL+"/v1/identities", token, map[string]any{
		"type": "bogus", "name": "X", "source_system": "manual",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("bad identity type: %d", status)
	}
	status, _ = do(t, http.MethodPost, e.srv.URL+"/v1/identities", token, "not-json")
	if status != http.StatusBadRequest {
		t.Fatalf("bad json: %d", status)
	}
}

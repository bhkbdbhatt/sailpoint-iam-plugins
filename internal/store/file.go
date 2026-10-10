package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentinel-iam/sentinel/internal/model"
)

const fileSnapshotVersion = 1

type userRecord struct {
	model.User
	PasswordHash string `json:"password_hash"`
}

type apiKeyRecord struct {
	model.APIKey
	Hash string `json:"hash"`
}

type connectorConfigRecord struct {
	model.ConnectorConfig
	Secrets map[string]string `json:"secrets,omitempty"`
}

type fileSnapshot struct {
	Version          int                              `json:"version"`
	Identities       map[string]model.Identity        `json:"identities"`
	Credentials      map[string]model.Credential      `json:"credentials"`
	Grants           map[string]model.AccessGrant     `json:"access_grants"`
	Resources        map[string]model.Resource        `json:"resources"`
	Tenants          map[string]model.Tenant          `json:"tenants"`
	Users            map[string]userRecord            `json:"users"`
	APIKeys          map[string]apiKeyRecord          `json:"api_keys"`
	ConnectorConfigs map[string]connectorConfigRecord `json:"connector_configs"`
	ConnectorRuns    map[string]model.ConnectorRun    `json:"connector_runs"`
	Policies         map[string]model.Policy          `json:"policies"`
	Alerts           map[string]model.Alert           `json:"alerts"`
}

// NewFile returns a Memory store backed by a JSON file at path. The file is
// created lazily on the first mutation. Existing data is loaded at boot.
func NewFile(path string) (*Memory, error) {
	m := NewMemory()
	m.path = path
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, fmt.Errorf("read store file: %w", err)
	}
	if len(data) == 0 {
		return m, nil
	}
	var snap fileSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parse store file: %w", err)
	}
	m.loadSnapshot(&snap)
	return m, nil
}

func (m *Memory) loadSnapshot(snap *fileSnapshot) {
	if snap.Identities != nil {
		m.identities = snap.Identities
	}
	if snap.Credentials != nil {
		m.credentials = snap.Credentials
	}
	if snap.Grants != nil {
		m.grants = snap.Grants
	}
	if snap.Resources != nil {
		m.resources = snap.Resources
	}
	if snap.Tenants != nil {
		m.tenants = snap.Tenants
	}
	for id, rec := range snap.Users {
		u := rec.User
		u.PasswordHash = rec.PasswordHash
		m.users[id] = u
	}
	for id, rec := range snap.APIKeys {
		k := rec.APIKey
		k.Hash = rec.Hash
		m.apiKeys[id] = k
	}
	for id, rec := range snap.ConnectorConfigs {
		c := rec.ConnectorConfig
		c.Secrets = rec.Secrets
		m.connConfigs[id] = c
	}
	if snap.ConnectorRuns != nil {
		m.connRuns = snap.ConnectorRuns
	}
	if snap.Policies != nil {
		m.policies = snap.Policies
	}
	if snap.Alerts != nil {
		m.alerts = snap.Alerts
	}
	m.rebuildIndexes()
}

func (m *Memory) rebuildIndexes() {
	m.identityExt = make(map[string]string, len(m.identities))
	for id, in := range m.identities {
		if in.ExternalID != "" {
			m.identityExt[extKey(in.TenantID, in.SourceSystem, in.ExternalID)] = id
		}
	}
	m.resourceExt = make(map[string]string, len(m.resources))
	for id, r := range m.resources {
		if r.ExternalID != "" {
			m.resourceExt[extKey(r.TenantID, r.SourceSystem, r.ExternalID)] = id
		}
	}
	m.userEmail = make(map[string]string, len(m.users))
	for id, u := range m.users {
		m.userEmail[strings.ToLower(u.Email)] = id
	}
	m.apiKeyHash = make(map[string]string, len(m.apiKeys))
	for id, k := range m.apiKeys {
		if k.Hash != "" {
			m.apiKeyHash[k.Hash] = id
		}
	}
	m.tenantSlug = make(map[string]string, len(m.tenants))
	for id, t := range m.tenants {
		m.tenantSlug[t.Slug] = id
	}
}

func (m *Memory) snapshotLocked() *fileSnapshot {
	snap := &fileSnapshot{
		Version:          fileSnapshotVersion,
		Identities:       make(map[string]model.Identity, len(m.identities)),
		Credentials:      make(map[string]model.Credential, len(m.credentials)),
		Grants:           make(map[string]model.AccessGrant, len(m.grants)),
		Resources:        make(map[string]model.Resource, len(m.resources)),
		Tenants:          make(map[string]model.Tenant, len(m.tenants)),
		Users:            make(map[string]userRecord, len(m.users)),
		APIKeys:          make(map[string]apiKeyRecord, len(m.apiKeys)),
		ConnectorConfigs: make(map[string]connectorConfigRecord, len(m.connConfigs)),
		ConnectorRuns:    make(map[string]model.ConnectorRun, len(m.connRuns)),
		Policies:         make(map[string]model.Policy, len(m.policies)),
		Alerts:           make(map[string]model.Alert, len(m.alerts)),
	}
	for k, v := range m.identities {
		snap.Identities[k] = v
	}
	for k, v := range m.credentials {
		snap.Credentials[k] = v
	}
	for k, v := range m.grants {
		snap.Grants[k] = v
	}
	for k, v := range m.resources {
		snap.Resources[k] = v
	}
	for k, v := range m.tenants {
		snap.Tenants[k] = v
	}
	for k, v := range m.users {
		snap.Users[k] = userRecord{User: v, PasswordHash: v.PasswordHash}
	}
	for k, v := range m.apiKeys {
		snap.APIKeys[k] = apiKeyRecord{APIKey: v, Hash: v.Hash}
	}
	for k, v := range m.connConfigs {
		snap.ConnectorConfigs[k] = connectorConfigRecord{ConnectorConfig: v, Secrets: v.Secrets}
	}
	for k, v := range m.connRuns {
		snap.ConnectorRuns[k] = v
	}
	for k, v := range m.policies {
		snap.Policies[k] = v
	}
	for k, v := range m.alerts {
		snap.Alerts[k] = v
	}
	return snap
}

// persistLocked writes the current state to disk. Callers must hold m.mu.
func (m *Memory) persistLocked() error {
	if m.path == "" {
		return nil
	}
	snap := m.snapshotLocked()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal store: %w", err)
	}
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create store dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".sentinel-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp store file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		cleanupTemp(tmp, tmpName)
		return fmt.Errorf("write store file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanupTemp(tmp, tmpName)
		return fmt.Errorf("chmod store file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close store file: %w", err)
	}
	if err := os.Rename(tmpName, m.path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace store file: %w", err)
	}
	return nil
}

// cleanupTemp best-effort closes and removes a partially written temp file.
func cleanupTemp(f *os.File, name string) {
	_ = f.Close()
	_ = os.Remove(name)
}

// Path returns the backing file path, or "" for an ephemeral store.
func (m *Memory) Path() string { return m.path }

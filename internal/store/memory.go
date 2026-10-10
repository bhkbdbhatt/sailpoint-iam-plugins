package store

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/sentinel-iam/sentinel/internal/model"
)

type Memory struct {
	mu sync.RWMutex

	path string

	identities  map[string]model.Identity
	credentials map[string]model.Credential
	grants      map[string]model.AccessGrant
	resources   map[string]model.Resource
	tenants     map[string]model.Tenant
	users       map[string]model.User
	apiKeys     map[string]model.APIKey
	connConfigs map[string]model.ConnectorConfig
	connRuns    map[string]model.ConnectorRun
	policies    map[string]model.Policy
	alerts      map[string]model.Alert

	identityExt map[string]string
	resourceExt map[string]string
	userEmail   map[string]string
	apiKeyHash  map[string]string
	tenantSlug  map[string]string
}

func NewMemory() *Memory {
	return &Memory{
		identities:  map[string]model.Identity{},
		credentials: map[string]model.Credential{},
		grants:      map[string]model.AccessGrant{},
		resources:   map[string]model.Resource{},
		tenants:     map[string]model.Tenant{},
		users:       map[string]model.User{},
		apiKeys:     map[string]model.APIKey{},
		connConfigs: map[string]model.ConnectorConfig{},
		connRuns:    map[string]model.ConnectorRun{},
		policies:    map[string]model.Policy{},
		alerts:      map[string]model.Alert{},
		identityExt: map[string]string{},
		resourceExt: map[string]string{},
		userEmail:   map[string]string{},
		apiKeyHash:  map[string]string{},
		tenantSlug:  map[string]string{},
	}
}

func extKey(tenantID, source, externalID string) string {
	return tenantID + "\x00" + source + "\x00" + externalID
}

func (m *Memory) Identities() IdentityStore      { return (*memoryIdentities)(m) }
func (m *Memory) Credentials() CredentialStore   { return (*memoryCredentials)(m) }
func (m *Memory) AccessGrants() AccessGrantStore { return (*memoryGrants)(m) }
func (m *Memory) Resources() ResourceStore       { return (*memoryResources)(m) }
func (m *Memory) Tenants() TenantStore           { return (*memoryTenants)(m) }
func (m *Memory) Users() UserStore               { return (*memoryUsers)(m) }
func (m *Memory) APIKeys() APIKeyStore           { return (*memoryAPIKeys)(m) }
func (m *Memory) Connectors() ConnectorStore     { return (*memoryConnectors)(m) }
func (m *Memory) Policies() PolicyStore          { return (*memoryPolicies)(m) }
func (m *Memory) Alerts() AlertStore             { return (*memoryAlerts)(m) }
func (m *Memory) Stats() StatsStore              { return (*memoryStats)(m) }

func (m *Memory) Ping(ctx context.Context) error { return ctx.Err() }
func (m *Memory) Close() error                   { return nil }

func (s *memoryIdentities) save() error  { return (*Memory)(s).persistLocked() }
func (s *memoryCredentials) save() error { return (*Memory)(s).persistLocked() }
func (s *memoryGrants) save() error      { return (*Memory)(s).persistLocked() }
func (s *memoryResources) save() error   { return (*Memory)(s).persistLocked() }
func (s *memoryTenants) save() error     { return (*Memory)(s).persistLocked() }
func (s *memoryUsers) save() error       { return (*Memory)(s).persistLocked() }
func (s *memoryAPIKeys) save() error     { return (*Memory)(s).persistLocked() }
func (s *memoryConnectors) save() error  { return (*Memory)(s).persistLocked() }
func (s *memoryPolicies) save() error    { return (*Memory)(s).persistLocked() }
func (s *memoryAlerts) save() error      { return (*Memory)(s).persistLocked() }

func applyLimitOffset(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

type memoryIdentities Memory

func (s *memoryIdentities) Upsert(ctx context.Context, in model.Identity) (model.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = now
	}
	in.UpdatedAt = now
	if in.Status == "" {
		in.Status = model.StatusActive
	}
	if err := in.Validate(); err != nil {
		return model.Identity{}, err
	}
	if in.ExternalID != "" {
		key := extKey(in.TenantID, in.SourceSystem, in.ExternalID)
		if existingID, ok := s.identityExt[key]; ok {
			existing := s.identities[existingID]
			in.ID = existing.ID
			in.CreatedAt = existing.CreatedAt
			s.identities[existing.ID] = in
			if err := s.save(); err != nil {
				return model.Identity{}, err
			}
			return in, nil
		}
		if old, ok := s.identities[in.ID]; ok && old.ExternalID != "" {
			delete(s.identityExt, extKey(old.TenantID, old.SourceSystem, old.ExternalID))
		}
		s.identityExt[key] = in.ID
	}
	s.identities[in.ID] = in
	if err := s.save(); err != nil {
		return model.Identity{}, err
	}
	return in, nil
}

func (s *memoryIdentities) Get(ctx context.Context, tenantID, id string) (model.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	in, ok := s.identities[id]
	if !ok || in.TenantID != tenantID {
		return model.Identity{}, model.ErrNotFound
	}
	return in, nil
}

func (s *memoryIdentities) GetByExternal(ctx context.Context, tenantID, sourceSystem, externalID string) (model.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.identityExt[extKey(tenantID, sourceSystem, externalID)]
	if !ok {
		return model.Identity{}, model.ErrNotFound
	}
	return s.identities[id], nil
}

func (s *memoryIdentities) List(ctx context.Context, tenantID string, f IdentityFilter) ([]model.Identity, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Identity
	q := strings.ToLower(strings.TrimSpace(f.Query))
	for _, in := range s.identities {
		if in.TenantID != tenantID {
			continue
		}
		if len(f.Types) > 0 && !containsType(f.Types, in.Type) {
			continue
		}
		if f.OwnerID != "" && in.OwnerID != f.OwnerID {
			continue
		}
		if f.Status != "" && in.Status != f.Status {
			continue
		}
		if f.SourceSystem != "" && in.SourceSystem != f.SourceSystem {
			continue
		}
		if f.MinRisk > 0 && in.RiskScore < f.MinRisk {
			continue
		}
		if f.MaxRisk > 0 && in.RiskScore > f.MaxRisk {
			continue
		}
		if q != "" && !matchesQuery(q, in.Name, in.DisplayName, in.ExternalID) {
			continue
		}
		out = append(out, in)
	}
	total := len(out)
	sortIdentities(out)
	lim, off := applyLimitOffset(f.Limit, f.Offset)
	if off >= total {
		return []model.Identity{}, total, nil
	}
	end := off + lim
	if end > total {
		end = total
	}
	return out[off:end], total, nil
}

func (s *memoryIdentities) Delete(ctx context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.identities[id]
	if !ok || in.TenantID != tenantID {
		return model.ErrNotFound
	}
	delete(s.identities, id)
	if in.ExternalID != "" {
		delete(s.identityExt, extKey(in.TenantID, in.SourceSystem, in.ExternalID))
	}
	return s.save()
}

func containsType(types []model.IdentityType, t model.IdentityType) bool {
	for _, x := range types {
		if x == t {
			return true
		}
	}
	return false
}

func matchesQuery(q string, fields ...string) bool {
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func sortIdentities(items []model.Identity) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].ID < items[j].ID
	})
}

type memoryCredentials Memory

func (s *memoryCredentials) Upsert(ctx context.Context, in model.Credential) (model.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = now
	}
	in.UpdatedAt = now
	if in.Status == "" {
		in.Status = model.StatusActive
	}
	if err := in.Validate(); err != nil {
		return model.Credential{}, err
	}
	if in.ExternalID != "" {
		for id, existing := range s.credentials {
			if existing.TenantID == in.TenantID && existing.SourceSystem == in.SourceSystem && existing.ExternalID == in.ExternalID {
				in.ID = existing.ID
				in.CreatedAt = existing.CreatedAt
				s.credentials[id] = in
				if err := s.save(); err != nil {
					return model.Credential{}, err
				}
				return in, nil
			}
		}
	}
	s.credentials[in.ID] = in
	if err := s.save(); err != nil {
		return model.Credential{}, err
	}
	return in, nil
}

func (s *memoryCredentials) Get(ctx context.Context, tenantID, id string) (model.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.credentials[id]
	if !ok || c.TenantID != tenantID {
		return model.Credential{}, model.ErrNotFound
	}
	return c, nil
}

func (s *memoryCredentials) List(ctx context.Context, tenantID string, f CredentialFilter) ([]model.Credential, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Credential
	now := time.Now().UTC()
	for _, c := range s.credentials {
		if c.TenantID != tenantID {
			continue
		}
		if f.IdentityID != "" && c.IdentityID != f.IdentityID {
			continue
		}
		if len(f.Types) > 0 && !containsCredType(f.Types, c.Type) {
			continue
		}
		if f.SourceSystem != "" && c.SourceSystem != f.SourceSystem {
			continue
		}
		if f.ExpiringWithinDays > 0 {
			if c.ExpiresAt == nil {
				continue
			}
			if c.ExpiresAt.After(now.AddDate(0, 0, f.ExpiringWithinDays)) {
				continue
			}
		}
		out = append(out, c)
	}
	total := len(out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	lim, off := applyLimitOffset(f.Limit, f.Offset)
	if off >= total {
		return []model.Credential{}, total, nil
	}
	end := off + lim
	if end > total {
		end = total
	}
	return out[off:end], total, nil
}

func (s *memoryCredentials) Delete(ctx context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[id]
	if !ok || c.TenantID != tenantID {
		return model.ErrNotFound
	}
	delete(s.credentials, id)
	return s.save()
}

func containsCredType(types []model.CredentialType, t model.CredentialType) bool {
	for _, x := range types {
		if x == t {
			return true
		}
	}
	return false
}

type memoryGrants Memory

func (s *memoryGrants) Upsert(ctx context.Context, in model.AccessGrant) (model.AccessGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = now
	}
	in.UpdatedAt = now
	if err := in.Validate(); err != nil {
		return model.AccessGrant{}, err
	}
	if in.ExternalID != "" {
		for id, existing := range s.grants {
			if existing.TenantID == in.TenantID && existing.SourceSystem == in.SourceSystem && existing.ExternalID == in.ExternalID {
				in.ID = existing.ID
				in.CreatedAt = existing.CreatedAt
				in.UsageCount30D = existing.UsageCount30D
				if in.LastUsedAt == nil {
					in.LastUsedAt = existing.LastUsedAt
				}
				s.grants[id] = in
				if err := s.save(); err != nil {
					return model.AccessGrant{}, err
				}
				return in, nil
			}
		}
	}
	s.grants[in.ID] = in
	if err := s.save(); err != nil {
		return model.AccessGrant{}, err
	}
	return in, nil
}

func (s *memoryGrants) Get(ctx context.Context, tenantID, id string) (model.AccessGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[id]
	if !ok || g.TenantID != tenantID {
		return model.AccessGrant{}, model.ErrNotFound
	}
	return g, nil
}

func (s *memoryGrants) List(ctx context.Context, tenantID string, f AccessGrantFilter) ([]model.AccessGrant, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.AccessGrant
	for _, g := range s.grants {
		if g.TenantID != tenantID {
			continue
		}
		if f.IdentityID != "" && g.IdentityID != f.IdentityID {
			continue
		}
		if f.ResourceID != "" && g.ResourceID != f.ResourceID {
			continue
		}
		if f.SourceSystem != "" && g.SourceSystem != f.SourceSystem {
			continue
		}
		out = append(out, g)
	}
	total := len(out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Entitlement != out[j].Entitlement {
			return out[i].Entitlement < out[j].Entitlement
		}
		return out[i].ID < out[j].ID
	})
	lim, off := applyLimitOffset(f.Limit, f.Offset)
	if off >= total {
		return []model.AccessGrant{}, total, nil
	}
	end := off + lim
	if end > total {
		end = total
	}
	return out[off:end], total, nil
}

func (s *memoryGrants) Delete(ctx context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok || g.TenantID != tenantID {
		return model.ErrNotFound
	}
	delete(s.grants, id)
	return s.save()
}

type memoryResources Memory

func (s *memoryResources) Upsert(ctx context.Context, in model.Resource) (model.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = now
	}
	in.UpdatedAt = now
	if err := in.Validate(); err != nil {
		return model.Resource{}, err
	}
	if in.ExternalID != "" {
		key := extKey(in.TenantID, in.SourceSystem, in.ExternalID)
		if existingID, ok := s.resourceExt[key]; ok {
			existing := s.resources[existingID]
			in.ID = existing.ID
			in.CreatedAt = existing.CreatedAt
			s.resources[existing.ID] = in
			if err := s.save(); err != nil {
				return model.Resource{}, err
			}
			return in, nil
		}
		s.resourceExt[key] = in.ID
	}
	s.resources[in.ID] = in
	if err := s.save(); err != nil {
		return model.Resource{}, err
	}
	return in, nil
}

func (s *memoryResources) Get(ctx context.Context, tenantID, id string) (model.Resource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.resources[id]
	if !ok || r.TenantID != tenantID {
		return model.Resource{}, model.ErrNotFound
	}
	return r, nil
}

func (s *memoryResources) GetByExternal(ctx context.Context, tenantID, sourceSystem, externalID string) (model.Resource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.resourceExt[extKey(tenantID, sourceSystem, externalID)]
	if !ok {
		return model.Resource{}, model.ErrNotFound
	}
	return s.resources[id], nil
}

func (s *memoryResources) List(ctx context.Context, tenantID string, f ResourceFilter) ([]model.Resource, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Resource
	q := strings.ToLower(strings.TrimSpace(f.Query))
	for _, r := range s.resources {
		if r.TenantID != tenantID {
			continue
		}
		if f.Type != "" && r.Type != f.Type {
			continue
		}
		if f.SourceSystem != "" && r.SourceSystem != f.SourceSystem {
			continue
		}
		if q != "" && !matchesQuery(q, r.Name, r.ExternalID) {
			continue
		}
		out = append(out, r)
	}
	total := len(out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	lim, off := applyLimitOffset(f.Limit, f.Offset)
	if off >= total {
		return []model.Resource{}, total, nil
	}
	end := off + lim
	if end > total {
		end = total
	}
	return out[off:end], total, nil
}

func (s *memoryResources) Delete(ctx context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.resources[id]
	if !ok || r.TenantID != tenantID {
		return model.ErrNotFound
	}
	delete(s.resources, id)
	if r.ExternalID != "" {
		delete(s.resourceExt, extKey(r.TenantID, r.SourceSystem, r.ExternalID))
	}
	return s.save()
}

type memoryTenants Memory

func (s *memoryTenants) Create(ctx context.Context, in model.Tenant) (model.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := in.Validate(); err != nil {
		return model.Tenant{}, err
	}
	if _, ok := s.tenantSlug[in.Slug]; ok {
		return model.Tenant{}, model.ErrConflict
	}
	now := time.Now().UTC()
	in.ID = uuid.NewString()
	in.CreatedAt = now
	in.UpdatedAt = now
	in.Status = model.StatusActive
	s.tenants[in.ID] = in
	s.tenantSlug[in.Slug] = in.ID
	if err := s.save(); err != nil {
		return model.Tenant{}, err
	}
	return in, nil
}

func (s *memoryTenants) Get(ctx context.Context, id string) (model.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	if !ok {
		return model.Tenant{}, model.ErrNotFound
	}
	return t, nil
}

func (s *memoryTenants) GetBySlug(ctx context.Context, slug string) (model.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.tenantSlug[slug]
	if !ok {
		return model.Tenant{}, model.ErrNotFound
	}
	return s.tenants[id], nil
}

func (s *memoryTenants) List(ctx context.Context) ([]model.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *memoryTenants) Count(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tenants), nil
}

type memoryUsers Memory

func (s *memoryUsers) Create(ctx context.Context, in model.User) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := in.Validate(); err != nil {
		return model.User{}, err
	}
	emails := strings.ToLower(in.Email)
	if _, ok := s.userEmail[emails]; ok {
		return model.User{}, model.ErrConflict
	}
	now := time.Now().UTC()
	in.ID = uuid.NewString()
	in.Email = emails
	in.CreatedAt = now
	in.UpdatedAt = now
	if in.Status == "" {
		in.Status = model.StatusActive
	}
	s.users[in.ID] = in
	s.userEmail[emails] = in.ID
	if err := s.save(); err != nil {
		return model.User{}, err
	}
	return in, nil
}

func (s *memoryUsers) Get(ctx context.Context, tenantID, id string) (model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok || u.TenantID != tenantID {
		return model.User{}, model.ErrNotFound
	}
	return u, nil
}

func (s *memoryUsers) GetByEmail(ctx context.Context, email string) (model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.userEmail[strings.ToLower(email)]
	if !ok {
		return model.User{}, model.ErrNotFound
	}
	return s.users[id], nil
}

func (s *memoryUsers) List(ctx context.Context, tenantID string, f UserFilter) ([]model.User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.User
	q := strings.ToLower(strings.TrimSpace(f.Query))
	for _, u := range s.users {
		if u.TenantID != tenantID {
			continue
		}
		if f.Role != "" && u.Role != f.Role {
			continue
		}
		if f.Status != "" && u.Status != f.Status {
			continue
		}
		if q != "" && !matchesQuery(q, u.Email, u.Name) {
			continue
		}
		out = append(out, u)
	}
	total := len(out)
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	lim, off := applyLimitOffset(f.Limit, f.Offset)
	if off >= total {
		return []model.User{}, total, nil
	}
	end := off + lim
	if end > total {
		end = total
	}
	return out[off:end], total, nil
}

func (s *memoryUsers) Update(ctx context.Context, in model.User) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.users[in.ID]
	if !ok {
		return model.User{}, model.ErrNotFound
	}
	if in.PasswordHash == "" {
		in.PasswordHash = existing.PasswordHash
	}
	in.CreatedAt = existing.CreatedAt
	in.UpdatedAt = time.Now().UTC()
	if err := in.Validate(); err != nil {
		return model.User{}, err
	}
	newEmail := strings.ToLower(in.Email)
	if newEmail != existing.Email {
		if _, taken := s.userEmail[newEmail]; taken {
			return model.User{}, model.ErrConflict
		}
		delete(s.userEmail, existing.Email)
		s.userEmail[newEmail] = in.ID
		in.Email = newEmail
	}
	s.users[in.ID] = in
	if err := s.save(); err != nil {
		return model.User{}, err
	}
	return in, nil
}

func (s *memoryUsers) Delete(ctx context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok || u.TenantID != tenantID {
		return model.ErrNotFound
	}
	delete(s.users, id)
	delete(s.userEmail, u.Email)
	return s.save()
}

type memoryAPIKeys Memory

func (s *memoryAPIKeys) Create(ctx context.Context, in model.APIKey) (model.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	if in.Hash == "" {
		return model.APIKey{}, model.ErrInvalid
	}
	if _, ok := s.apiKeyHash[in.Hash]; ok {
		return model.APIKey{}, model.ErrConflict
	}
	in.CreatedAt = time.Now().UTC()
	s.apiKeys[in.ID] = in
	s.apiKeyHash[in.Hash] = in.ID
	if err := s.save(); err != nil {
		return model.APIKey{}, err
	}
	return in, nil
}

func (s *memoryAPIKeys) Get(ctx context.Context, tenantID, id string) (model.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.apiKeys[id]
	if !ok || k.TenantID != tenantID {
		return model.APIKey{}, model.ErrNotFound
	}
	return k, nil
}

func (s *memoryAPIKeys) GetByHash(ctx context.Context, hash string) (model.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.apiKeyHash[hash]
	if !ok {
		return model.APIKey{}, model.ErrNotFound
	}
	return s.apiKeys[id], nil
}

func (s *memoryAPIKeys) List(ctx context.Context, tenantID string, f APIKeyFilter) ([]model.APIKey, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.APIKey
	for _, k := range s.apiKeys {
		if k.TenantID != tenantID {
			continue
		}
		if f.UserID != "" && k.UserID != f.UserID {
			continue
		}
		if f.Revoked != nil && k.Revoked != *f.Revoked {
			continue
		}
		k.Hash = ""
		out = append(out, k)
	}
	total := len(out)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	lim, off := applyLimitOffset(f.Limit, f.Offset)
	if off >= total {
		return []model.APIKey{}, total, nil
	}
	end := off + lim
	if end > total {
		end = total
	}
	return out[off:end], total, nil
}

func (s *memoryAPIKeys) Update(ctx context.Context, in model.APIKey) (model.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.apiKeys[in.ID]
	if !ok {
		return model.APIKey{}, model.ErrNotFound
	}
	in.Hash = existing.Hash
	in.Prefix = existing.Prefix
	in.CreatedAt = existing.CreatedAt
	s.apiKeys[in.ID] = in
	if err := s.save(); err != nil {
		return model.APIKey{}, err
	}
	return in, nil
}

func (s *memoryAPIKeys) Delete(ctx context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.apiKeys[id]
	if !ok || k.TenantID != tenantID {
		return model.ErrNotFound
	}
	delete(s.apiKeys, id)
	delete(s.apiKeyHash, k.Hash)
	return s.save()
}

type memoryConnectors Memory

func (s *memoryConnectors) CreateConfig(ctx context.Context, in model.ConnectorConfig) (model.ConnectorConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := in.Validate(); err != nil {
		return model.ConnectorConfig{}, err
	}
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	in.CreatedAt = now
	in.UpdatedAt = now
	if in.LastStatus == "" {
		in.LastStatus = model.ConnectorStatusIdle
	}
	s.connConfigs[in.ID] = in
	if err := s.save(); err != nil {
		return model.ConnectorConfig{}, err
	}
	return in, nil
}

func (s *memoryConnectors) GetConfig(ctx context.Context, tenantID, id string) (model.ConnectorConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.connConfigs[id]
	if !ok || c.TenantID != tenantID {
		return model.ConnectorConfig{}, model.ErrNotFound
	}
	return c, nil
}

func (s *memoryConnectors) ListConfigs(ctx context.Context, tenantID string, f ConnectorFilter) ([]model.ConnectorConfig, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.ConnectorConfig
	for _, c := range s.connConfigs {
		if c.TenantID != tenantID {
			continue
		}
		if f.Key != "" && c.Key != f.Key {
			continue
		}
		if f.Enabled != nil && c.Enabled != *f.Enabled {
			continue
		}
		out = append(out, c)
	}
	total := len(out)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	lim, off := applyLimitOffset(f.Limit, f.Offset)
	if off >= total {
		return []model.ConnectorConfig{}, total, nil
	}
	end := off + lim
	if end > total {
		end = total
	}
	return out[off:end], total, nil
}

func (s *memoryConnectors) UpdateConfig(ctx context.Context, in model.ConnectorConfig) (model.ConnectorConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.connConfigs[in.ID]
	if !ok || existing.TenantID != in.TenantID {
		return model.ConnectorConfig{}, model.ErrNotFound
	}
	if len(in.Secrets) == 0 {
		in.Secrets = existing.Secrets
	}
	in.CreatedAt = existing.CreatedAt
	in.UpdatedAt = time.Now().UTC()
	if err := in.Validate(); err != nil {
		return model.ConnectorConfig{}, err
	}
	s.connConfigs[in.ID] = in
	if err := s.save(); err != nil {
		return model.ConnectorConfig{}, err
	}
	return in, nil
}

func (s *memoryConnectors) DeleteConfig(ctx context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.connConfigs[id]
	if !ok || c.TenantID != tenantID {
		return model.ErrNotFound
	}
	delete(s.connConfigs, id)
	return s.save()
}

func (s *memoryConnectors) CreateRun(ctx context.Context, in model.ConnectorRun) (model.ConnectorRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	s.connRuns[in.ID] = in
	if err := s.save(); err != nil {
		return model.ConnectorRun{}, err
	}
	return in, nil
}

func (s *memoryConnectors) UpdateRun(ctx context.Context, in model.ConnectorRun) (model.ConnectorRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.connRuns[in.ID]
	if !ok || existing.TenantID != in.TenantID {
		return model.ConnectorRun{}, model.ErrNotFound
	}
	s.connRuns[in.ID] = in
	if err := s.save(); err != nil {
		return model.ConnectorRun{}, err
	}
	return in, nil
}

func (s *memoryConnectors) GetRun(ctx context.Context, tenantID, id string) (model.ConnectorRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.connRuns[id]
	if !ok || r.TenantID != tenantID {
		return model.ConnectorRun{}, model.ErrNotFound
	}
	return r, nil
}

func (s *memoryConnectors) ListRuns(ctx context.Context, tenantID string, f ConnectorRunFilter) ([]model.ConnectorRun, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.ConnectorRun
	for _, r := range s.connRuns {
		if r.TenantID != tenantID {
			continue
		}
		if f.ConfigID != "" && r.ConnectorConfigID != f.ConfigID {
			continue
		}
		if f.Status != "" && r.Status != f.Status {
			continue
		}
		out = append(out, r)
	}
	total := len(out)
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	lim, off := applyLimitOffset(f.Limit, f.Offset)
	if off >= total {
		return []model.ConnectorRun{}, total, nil
	}
	end := off + lim
	if end > total {
		end = total
	}
	return out[off:end], total, nil
}

type memoryStats Memory

func (s *memoryStats) Overview(ctx context.Context, tenantID string) (model.Overview, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ov := model.Overview{
		IdentitiesByType:   map[string]int{},
		IdentitiesByStatus: map[string]int{},
		RiskBuckets:        map[string]int{string(model.RiskLow): 0, string(model.RiskMedium): 0, string(model.RiskHigh): 0, string(model.RiskCritical): 0},
	}
	for _, in := range s.identities {
		if in.TenantID != tenantID {
			continue
		}
		ov.TotalIdentities++
		ov.IdentitiesByType[string(in.Type)]++
		ov.IdentitiesByStatus[string(in.Status)]++
		ov.RiskBuckets[string(model.BucketForRisk(in.RiskScore))]++
		if in.OwnerID == "" {
			ov.UnownedIdentities++
		}
	}
	if ov.TotalIdentities > 0 {
		ov.OwnerCoveragePct = float64(ov.TotalIdentities-ov.UnownedIdentities) / float64(ov.TotalIdentities) * 100
	}
	now := time.Now().UTC()
	for _, c := range s.credentials {
		if c.TenantID != tenantID {
			continue
		}
		ov.TotalCredentials++
		if c.ExpiresAt != nil && c.ExpiresAt.After(now) && !c.ExpiresAt.After(now.AddDate(0, 0, 30)) {
			ov.CredentialsExpiring30++
		}
	}
	for _, g := range s.grants {
		if g.TenantID == tenantID {
			ov.TotalGrants++
		}
	}
	for _, r := range s.resources {
		if r.TenantID == tenantID {
			ov.TotalResources++
		}
	}
	for _, run := range s.connRuns {
		if run.TenantID != tenantID || run.FinishedAt == nil {
			continue
		}
		if ov.LastConnectorRunAt == nil || run.FinishedAt.After(*ov.LastConnectorRunAt) {
			t := *run.FinishedAt
			ov.LastConnectorRunAt = &t
		}
	}
	return ov, nil
}

type memoryPolicies Memory

func (s *memoryPolicies) Create(ctx context.Context, in model.Policy) (model.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	in.CreatedAt = now
	in.UpdatedAt = now
	if in.Status == "" {
		in.Status = model.PolicyDraft
	}
	if err := in.Validate(); err != nil {
		return model.Policy{}, err
	}
	s.policies[in.ID] = in
	if err := s.save(); err != nil {
		return model.Policy{}, err
	}
	return in, nil
}

func (s *memoryPolicies) Get(ctx context.Context, tenantID, id string) (model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok || p.TenantID != tenantID {
		return model.Policy{}, model.ErrNotFound
	}
	return p, nil
}

func (s *memoryPolicies) List(ctx context.Context, tenantID string, f PolicyFilter) ([]model.Policy, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Policy
	q := strings.ToLower(strings.TrimSpace(f.Query))
	for _, p := range s.policies {
		if p.TenantID != tenantID {
			continue
		}
		if f.IntentLevel != "" && p.IntentLevel != f.IntentLevel {
			continue
		}
		if f.Status != "" && p.Status != f.Status {
			continue
		}
		if f.Engine != "" && p.Engine != f.Engine {
			continue
		}
		if q != "" && !matchesQuery(q, p.Name, p.Scope, p.Engine) {
			continue
		}
		out = append(out, p)
	}
	total := len(out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	lim, off := applyLimitOffset(f.Limit, f.Offset)
	if off >= total {
		return []model.Policy{}, total, nil
	}
	end := off + lim
	if end > total {
		end = total
	}
	return out[off:end], total, nil
}

func (s *memoryPolicies) Update(ctx context.Context, in model.Policy) (model.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.policies[in.ID]
	if !ok || existing.TenantID != in.TenantID {
		return model.Policy{}, model.ErrNotFound
	}
	in.CreatedAt = existing.CreatedAt
	in.UpdatedAt = time.Now().UTC()
	if err := in.Validate(); err != nil {
		return model.Policy{}, err
	}
	s.policies[in.ID] = in
	if err := s.save(); err != nil {
		return model.Policy{}, err
	}
	return in, nil
}

func (s *memoryPolicies) Delete(ctx context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[id]
	if !ok || p.TenantID != tenantID {
		return model.ErrNotFound
	}
	delete(s.policies, id)
	return s.save()
}

type memoryAlerts Memory

func (s *memoryAlerts) Create(ctx context.Context, in model.Alert) (model.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	in.CreatedAt = now
	in.UpdatedAt = now
	if in.Status == "" {
		in.Status = model.AlertOpen
	}
	if in.DetectedAt.IsZero() {
		in.DetectedAt = now
	}
	if err := in.Validate(); err != nil {
		return model.Alert{}, err
	}
	s.alerts[in.ID] = in
	if err := s.save(); err != nil {
		return model.Alert{}, err
	}
	return in, nil
}

func (s *memoryAlerts) Get(ctx context.Context, tenantID, id string) (model.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.alerts[id]
	if !ok || a.TenantID != tenantID {
		return model.Alert{}, model.ErrNotFound
	}
	return a, nil
}

func (s *memoryAlerts) List(ctx context.Context, tenantID string, f AlertFilter) ([]model.Alert, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Alert
	for _, a := range s.alerts {
		if a.TenantID != tenantID {
			continue
		}
		if f.IdentityID != "" && a.IdentityID != f.IdentityID {
			continue
		}
		if f.Type != "" && a.Type != f.Type {
			continue
		}
		if f.Severity != "" && a.Severity != f.Severity {
			continue
		}
		if f.Status != "" && a.Status != f.Status {
			continue
		}
		out = append(out, a)
	}
	total := len(out)
	sort.Slice(out, func(i, j int) bool { return out[i].DetectedAt.After(out[j].DetectedAt) })
	lim, off := applyLimitOffset(f.Limit, f.Offset)
	if off >= total {
		return []model.Alert{}, total, nil
	}
	end := off + lim
	if end > total {
		end = total
	}
	return out[off:end], total, nil
}

func (s *memoryAlerts) Update(ctx context.Context, in model.Alert) (model.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.alerts[in.ID]
	if !ok || existing.TenantID != in.TenantID {
		return model.Alert{}, model.ErrNotFound
	}
	in.CreatedAt = existing.CreatedAt
	in.UpdatedAt = time.Now().UTC()
	if err := in.Validate(); err != nil {
		return model.Alert{}, err
	}
	s.alerts[in.ID] = in
	if err := s.save(); err != nil {
		return model.Alert{}, err
	}
	return in, nil
}

func (s *memoryAlerts) Delete(ctx context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[id]
	if !ok || a.TenantID != tenantID {
		return model.ErrNotFound
	}
	delete(s.alerts, id)
	return s.save()
}

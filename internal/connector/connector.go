package connector

import (
	"context"
	"fmt"

	"github.com/sentinel-iam/sentinel/internal/model"
)

// Result is the set of discovered IAM records produced by a connector run.
type Result struct {
	Identities  []model.Identity
	Credentials []model.Credential
	Grants      []model.AccessGrant
	Resources   []model.Resource
}

// Connector discovers IAM state from an external system.
type Connector interface {
	Key() model.ConnectorKey
	Discover(ctx context.Context, tenantID string, cfg model.ConnectorConfig) (*Result, error)
}

// Registry maps connector keys to their implementations.
type Registry struct {
	connectors map[model.ConnectorKey]Connector
}

func NewRegistry() *Registry {
	return &Registry{connectors: map[model.ConnectorKey]Connector{}}
}

func (r *Registry) Register(c Connector) {
	r.connectors[c.Key()] = c
}

func (r *Registry) Get(key model.ConnectorKey) (Connector, bool) {
	c, ok := r.connectors[key]
	return c, ok
}

func (r *Registry) Keys() []model.ConnectorKey {
	out := make([]model.ConnectorKey, 0, len(r.connectors))
	for k := range r.connectors {
		out = append(out, k)
	}
	return out
}

// Default builds the registry of connectors available in this build.
func Default() *Registry {
	r := NewRegistry()
	r.Register(Simulated{})
	r.Register(NewAWSIAM())
	return r
}

// notImplemented is returned when a configured connector has no implementation.
func notImplemented(key model.ConnectorKey) error {
	return fmt.Errorf("connector %q is not implemented in this build", key)
}

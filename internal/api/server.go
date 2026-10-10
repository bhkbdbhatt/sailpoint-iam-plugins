package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/sentinel-iam/sentinel/internal/auth"
	"github.com/sentinel-iam/sentinel/internal/connector"
	"github.com/sentinel-iam/sentinel/internal/secrets"
	"github.com/sentinel-iam/sentinel/internal/store"
)

type Server struct {
	store       store.Store
	jwt         *auth.JWTManager
	box         *secrets.Box
	runner      *connector.Runner
	log         *slog.Logger
	loginGuard  *loginGuard
	corsOrigins []string
	metrics     bool
}

type Option func(*Server)

// WithCORS sets the allowed origins for the CORS middleware.
func WithCORS(origins []string) Option {
	return func(s *Server) { s.corsOrigins = origins }
}

// WithMetrics enables or disables the Prometheus /metrics endpoint.
func WithMetrics(enabled bool) Option {
	return func(s *Server) { s.metrics = enabled }
}

func New(st store.Store, jwt *auth.JWTManager, box *secrets.Box, runner *connector.Runner, log *slog.Logger, opts ...Option) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		store:      st,
		jwt:        jwt,
		box:        box,
		runner:     runner,
		log:        log,
		loginGuard: newLoginGuard(5, time.Minute),
		metrics:    true,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(s.cors)
	r.Use(securityHeaders)
	if s.metrics {
		r.Use(s.recordMetrics)
	}
	r.Use(bodyLimit)
	r.Use(s.recoverer)
	r.Use(s.requestLogger)

	if s.metrics {
		r.Get("/metrics", s.metricsHandler)
	}
	r.Get("/healthz", s.healthz)
	r.Get("/readyz", s.readyz)
	r.Get("/openapi.yaml", s.openapiSpec)
	r.Get("/docs", s.apiDocs)

	r.Route("/v1", func(r chi.Router) {
		r.Post("/auth/login", s.login)

		r.Group(func(r chi.Router) {
			r.Use(s.authenticate)

			r.Get("/auth/me", s.me)

			r.With(s.requirePerm(auth.PermTenantsRead)).Get("/tenants", s.listTenants)
			r.With(s.requirePerm(auth.PermTenantsWrite)).Post("/tenants", s.createTenant)
			r.With(s.requirePerm(auth.PermTenantsRead)).Get("/tenants/{id}", s.getTenant)

			r.With(s.requirePerm(auth.PermUsersRead)).Get("/users", s.listUsers)
			r.With(s.requirePerm(auth.PermUsersWrite)).Post("/users", s.createUser)
			r.With(s.requirePerm(auth.PermUsersRead)).Get("/users/{id}", s.getUser)
			r.With(s.requirePerm(auth.PermUsersWrite)).Put("/users/{id}", s.updateUser)
			r.With(s.requirePerm(auth.PermUsersWrite)).Delete("/users/{id}", s.deleteUser)

			r.With(s.requirePerm(auth.PermAPIKeysWrite)).Get("/apikeys", s.listAPIKeys)
			r.With(s.requirePerm(auth.PermAPIKeysWrite)).Post("/apikeys", s.createAPIKey)
			r.With(s.requirePerm(auth.PermAPIKeysWrite)).Delete("/apikeys/{id}", s.revokeAPIKey)

			r.With(s.requirePerm(auth.PermIdentitiesRead)).Get("/identities", s.listIdentities)
			r.With(s.requirePerm(auth.PermIdentitiesWrite)).Post("/identities", s.createIdentity)
			r.With(s.requirePerm(auth.PermIdentitiesRead)).Get("/identities/{id}", s.getIdentity)
			r.With(s.requirePerm(auth.PermIdentitiesWrite)).Put("/identities/{id}", s.updateIdentity)
			r.With(s.requirePerm(auth.PermIdentitiesWrite)).Delete("/identities/{id}", s.deleteIdentity)

			r.With(s.requirePerm(auth.PermCredentialsRead)).Get("/credentials", s.listCredentials)
			r.With(s.requirePerm(auth.PermCredentialsRead)).Get("/credentials/{id}", s.getCredential)

			r.With(s.requirePerm(auth.PermGrantsRead)).Get("/grants", s.listGrants)
			r.With(s.requirePerm(auth.PermGrantsRead)).Get("/grants/{id}", s.getGrant)

			r.With(s.requirePerm(auth.PermResourcesRead)).Get("/resources", s.listResources)
			r.With(s.requirePerm(auth.PermResourcesRead)).Get("/resources/{id}", s.getResource)

			r.With(s.requirePerm(auth.PermConnectorsRead)).Get("/connectors", s.listConnectors)
			r.With(s.requirePerm(auth.PermConnectorsWrite)).Post("/connectors", s.createConnector)
			r.With(s.requirePerm(auth.PermConnectorsRead)).Get("/connectors/{id}", s.getConnector)
			r.With(s.requirePerm(auth.PermConnectorsWrite)).Put("/connectors/{id}", s.updateConnector)
			r.With(s.requirePerm(auth.PermConnectorsWrite)).Delete("/connectors/{id}", s.deleteConnector)
			r.With(s.requirePerm(auth.PermConnectorsRun)).Post("/connectors/{id}/run", s.runConnector)
			r.With(s.requirePerm(auth.PermConnectorsRead)).Get("/connectors/{id}/runs", s.listConnectorRuns)

			r.With(s.requirePerm(auth.PermPoliciesRead)).Get("/policies", s.listPolicies)
			r.With(s.requirePerm(auth.PermPoliciesWrite)).Post("/policies", s.createPolicy)
			r.With(s.requirePerm(auth.PermPoliciesRead)).Get("/policies/{id}", s.getPolicy)
			r.With(s.requirePerm(auth.PermPoliciesWrite)).Put("/policies/{id}", s.updatePolicy)
			r.With(s.requirePerm(auth.PermPoliciesWrite)).Delete("/policies/{id}", s.deletePolicy)

			r.With(s.requirePerm(auth.PermAlertsRead)).Get("/alerts", s.listAlerts)
			r.With(s.requirePerm(auth.PermAlertsWrite)).Post("/alerts", s.createAlert)
			r.With(s.requirePerm(auth.PermAlertsRead)).Get("/alerts/{id}", s.getAlert)
			r.With(s.requirePerm(auth.PermAlertsWrite)).Patch("/alerts/{id}", s.patchAlert)
			r.With(s.requirePerm(auth.PermAlertsWrite)).Delete("/alerts/{id}", s.deleteAlert)

			r.With(s.requirePerm(auth.PermStatsRead)).Get("/stats/overview", s.overview)
		})
	})

	return r
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: errorBody{Code: "unavailable", Message: "store unavailable"}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		s.log.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic recovered", "error", rec, "path", r.URL.Path)
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: errorBody{Code: "internal_error", Message: "internal server error"}})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func queryInt(q string, def int) int {
	if q == "" {
		return def
	}
	n, err := strconv.Atoi(q)
	if err != nil {
		return def
	}
	return n
}

func (s *Server) page(r *http.Request) (int, int) {
	return queryInt(r.URL.Query().Get("limit"), 0), queryInt(r.URL.Query().Get("offset"), 0)
}

package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/store"
)

type connectorRequest struct {
	Key             model.ConnectorKey `json:"key"`
	Name            string             `json:"name"`
	Enabled         bool               `json:"enabled"`
	IntervalMinutes int                `json:"interval_minutes"`
	Secrets         map[string]string  `json:"secrets"`
	Options         map[string]string  `json:"options"`
}

func (s *Server) listConnectors(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	q := r.URL.Query()
	limit, offset := s.page(r)
	f := store.ConnectorFilter{
		Key:    model.ConnectorKey(q.Get("key")),
		Limit:  limit,
		Offset: offset,
	}
	if ev := q.Get("enabled"); ev != "" {
		b := ev == "true"
		f.Enabled = &b
	}
	items, total, err := s.store.Connectors().ListConfigs(r.Context(), p.TenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, items, total, limit, offset)
}

func (s *Server) createConnector(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var req connectorRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	encrypted, err := s.encryptSecrets(req.Secrets)
	if err != nil {
		writeError(w, err)
		return
	}
	in := model.ConnectorConfig{
		TenantID:        p.TenantID,
		Key:             req.Key,
		Name:            req.Name,
		Enabled:         req.Enabled,
		IntervalMinutes: req.IntervalMinutes,
		Secrets:         encrypted,
		Options:         req.Options,
	}
	out, err := s.store.Connectors().CreateConfig(r.Context(), in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getConnector(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	out, err := s.store.Connectors().GetConfig(r.Context(), p.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateConnector(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	id := chi.URLParam(r, "id")
	existing, err := s.store.Connectors().GetConfig(r.Context(), p.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	var req connectorRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	if req.Key != "" {
		existing.Key = req.Key
	}
	if req.Name != "" {
		existing.Name = req.Name
	}
	existing.Enabled = req.Enabled
	existing.IntervalMinutes = req.IntervalMinutes
	if req.Options != nil {
		existing.Options = req.Options
	}
	if len(req.Secrets) > 0 {
		encrypted, err := s.encryptSecrets(req.Secrets)
		if err != nil {
			writeError(w, err)
			return
		}
		existing.Secrets = encrypted
	}
	out, err := s.store.Connectors().UpdateConfig(r.Context(), existing)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteConnector(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	if err := s.store.Connectors().DeleteConfig(r.Context(), p.TenantID, chi.URLParam(r, "id")); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) runConnector(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	run, err := s.runner.Run(r.Context(), p.TenantID, chi.URLParam(r, "id"), "manual")
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) listConnectorRuns(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	limit, offset := s.page(r)
	f := store.ConnectorRunFilter{
		ConfigID: chi.URLParam(r, "id"),
		Status:   model.ConnectorStatus(r.URL.Query().Get("status")),
		Limit:    limit,
		Offset:   offset,
	}
	items, total, err := s.store.Connectors().ListRuns(r.Context(), p.TenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, items, total, limit, offset)
}

func (s *Server) encryptSecrets(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		enc, err := s.box.Encrypt(v)
		if err != nil {
			return nil, err
		}
		out[k] = enc
	}
	return out, nil
}

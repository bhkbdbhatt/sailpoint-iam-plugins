package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/store"
)

type patchAlertRequest struct {
	Status            model.AlertStatus `json:"status"`
	RecommendedAction string            `json:"recommended_action"`
	Description       string            `json:"description"`
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	q := r.URL.Query()
	limit, offset := s.page(r)
	f := store.AlertFilter{
		IdentityID: q.Get("identity_id"),
		Type:       q.Get("type"),
		Severity:   model.AlertSeverity(q.Get("severity")),
		Status:     model.AlertStatus(q.Get("status")),
		Limit:      limit,
		Offset:     offset,
	}
	items, total, err := s.store.Alerts().List(r.Context(), p.TenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, items, total, limit, offset)
}

func (s *Server) createAlert(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var in model.Alert
	if err := decodeJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	in.ID = ""
	in.TenantID = p.TenantID
	out, err := s.store.Alerts().Create(r.Context(), in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	out, err := s.store.Alerts().Get(r.Context(), p.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) patchAlert(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	id := chi.URLParam(r, "id")
	existing, err := s.store.Alerts().Get(r.Context(), p.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	var req patchAlertRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	if req.Status != "" {
		existing.Status = req.Status
	}
	if req.RecommendedAction != "" {
		existing.RecommendedAction = req.RecommendedAction
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	out, err := s.store.Alerts().Update(r.Context(), existing)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteAlert(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	if err := s.store.Alerts().Delete(r.Context(), p.TenantID, chi.URLParam(r, "id")); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

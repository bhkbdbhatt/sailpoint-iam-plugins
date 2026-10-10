package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/store"
)

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	q := r.URL.Query()
	limit, offset := s.page(r)
	f := store.PolicyFilter{
		IntentLevel: model.IntentLevel(q.Get("intent_level")),
		Status:      model.PolicyStatus(q.Get("status")),
		Engine:      q.Get("engine"),
		Query:       q.Get("q"),
		Limit:       limit,
		Offset:      offset,
	}
	items, total, err := s.store.Policies().List(r.Context(), p.TenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, items, total, limit, offset)
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var in model.Policy
	if err := decodeJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	in.ID = ""
	in.TenantID = p.TenantID
	out, err := s.store.Policies().Create(r.Context(), in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	out, err := s.store.Policies().Get(r.Context(), p.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	id := chi.URLParam(r, "id")
	existing, err := s.store.Policies().Get(r.Context(), p.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	var in model.Policy
	if err := decodeJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	in.ID = existing.ID
	in.TenantID = existing.TenantID
	in.CreatedAt = existing.CreatedAt
	if in.Name == "" {
		in.Name = existing.Name
	}
	if in.Engine == "" {
		in.Engine = existing.Engine
	}
	if in.IntentLevel == "" {
		in.IntentLevel = existing.IntentLevel
	}
	if in.Status == "" {
		in.Status = existing.Status
	}
	out, err := s.store.Policies().Update(r.Context(), in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	if err := s.store.Policies().Delete(r.Context(), p.TenantID, chi.URLParam(r, "id")); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

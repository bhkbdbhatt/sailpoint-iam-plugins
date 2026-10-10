package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/store"
)

func (s *Server) listIdentities(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	q := r.URL.Query()
	limit, offset := s.page(r)
	f := store.IdentityFilter{
		Query:        q.Get("q"),
		OwnerID:      q.Get("owner_id"),
		Status:       model.Status(q.Get("status")),
		SourceSystem: q.Get("source_system"),
		MinRisk:      queryInt(q.Get("min_risk"), 0),
		MaxRisk:      queryInt(q.Get("max_risk"), 0),
		Limit:        limit,
		Offset:       offset,
	}
	if types := q.Get("types"); types != "" {
		for _, t := range strings.Split(types, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			f.Types = append(f.Types, model.IdentityType(t))
		}
	}
	items, total, err := s.store.Identities().List(r.Context(), p.TenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, items, total, limit, offset)
}

func (s *Server) createIdentity(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var in model.Identity
	if err := decodeJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	in.ID = ""
	in.TenantID = p.TenantID
	out, err := s.store.Identities().Upsert(r.Context(), in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getIdentity(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	out, err := s.store.Identities().Get(r.Context(), p.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateIdentity(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	id := chi.URLParam(r, "id")
	existing, err := s.store.Identities().Get(r.Context(), p.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	var in model.Identity
	if err := decodeJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	in.ID = existing.ID
	in.TenantID = existing.TenantID
	in.CreatedAt = existing.CreatedAt
	if in.SourceSystem == "" {
		in.SourceSystem = existing.SourceSystem
	}
	if in.ExternalID == "" {
		in.ExternalID = existing.ExternalID
	}
	if in.Type == "" {
		in.Type = existing.Type
	}
	if in.Status == "" {
		in.Status = existing.Status
	}
	if in.Name == "" {
		in.Name = existing.Name
	}
	out, err := s.store.Identities().Upsert(r.Context(), in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteIdentity(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	if err := s.store.Identities().Delete(r.Context(), p.TenantID, chi.URLParam(r, "id")); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

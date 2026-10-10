package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/sentinel-iam/sentinel/internal/store"
)

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	q := r.URL.Query()
	limit, offset := s.page(r)
	f := store.AccessGrantFilter{
		IdentityID:   q.Get("identity_id"),
		ResourceID:   q.Get("resource_id"),
		SourceSystem: q.Get("source_system"),
		Limit:        limit,
		Offset:       offset,
	}
	items, total, err := s.store.AccessGrants().List(r.Context(), p.TenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, items, total, limit, offset)
}

func (s *Server) getGrant(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	out, err := s.store.AccessGrants().Get(r.Context(), p.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/store"
)

func (s *Server) listResources(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	q := r.URL.Query()
	limit, offset := s.page(r)
	f := store.ResourceFilter{
		Query:        q.Get("q"),
		Type:         model.ResourceType(q.Get("type")),
		SourceSystem: q.Get("source_system"),
		Limit:        limit,
		Offset:       offset,
	}
	items, total, err := s.store.Resources().List(r.Context(), p.TenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, items, total, limit, offset)
}

func (s *Server) getResource(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	out, err := s.store.Resources().Get(r.Context(), p.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

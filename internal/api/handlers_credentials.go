package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/store"
)

func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	q := r.URL.Query()
	limit, offset := s.page(r)
	f := store.CredentialFilter{
		IdentityID:         q.Get("identity_id"),
		SourceSystem:       q.Get("source_system"),
		ExpiringWithinDays: queryInt(q.Get("expiring_within_days"), 0),
		Limit:              limit,
		Offset:             offset,
	}
	if types := q.Get("types"); types != "" {
		for _, t := range strings.Split(types, ",") {
			if t = strings.TrimSpace(t); t != "" {
				f.Types = append(f.Types, model.CredentialType(t))
			}
		}
	}
	items, total, err := s.store.Credentials().List(r.Context(), p.TenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, items, total, limit, offset)
}

func (s *Server) getCredential(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	out, err := s.store.Credentials().Get(r.Context(), p.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

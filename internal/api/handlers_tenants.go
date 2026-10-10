package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/sentinel-iam/sentinel/internal/model"
)

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.store.Tenants().List(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, tenants, len(tenants), len(tenants), 0)
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var in model.Tenant
	if err := decodeJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	out, err := s.store.Tenants().Create(r.Context(), in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.Tenants().Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

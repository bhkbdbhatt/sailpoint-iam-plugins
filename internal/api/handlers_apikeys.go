package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sentinel-iam/sentinel/internal/auth"
	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/store"
)

type createAPIKeyRequest struct {
	Name      string     `json:"name"`
	Role      model.Role `json:"role"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type createAPIKeyResponse struct {
	model.APIKey
	Token string `json:"token"`
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	q := r.URL.Query()
	limit, offset := s.page(r)
	f := store.APIKeyFilter{
		UserID: q.Get("user_id"),
		Limit:  limit,
		Offset: offset,
	}
	if rv := q.Get("revoked"); rv != "" {
		b := rv == "true"
		f.Revoked = &b
	}
	keys, total, err := s.store.APIKeys().List(r.Context(), p.TenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, keys, total, limit, offset)
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var req createAPIKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	if req.Role == "" {
		req.Role = p.Role
	}
	if !req.Role.Valid() {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "validation_error", Message: "invalid role"}})
		return
	}
	if !auth.Can(p.Role, auth.PermAPIKeysWrite) {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: errorBody{Code: "forbidden", Message: "cannot issue api keys"}})
		return
	}
	if req.Role != p.Role && p.Role != model.RoleOwner {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: errorBody{Code: "forbidden", Message: "only owners can issue keys with a different role"}})
		return
	}
	mat, err := auth.GenerateAPIKey()
	if err != nil {
		writeError(w, err)
		return
	}
	in := model.APIKey{
		TenantID:  p.TenantID,
		UserID:    p.UserID,
		Name:      req.Name,
		Prefix:    mat.Prefix,
		Hash:      mat.Hash,
		Role:      req.Role,
		ExpiresAt: req.ExpiresAt,
	}
	out, err := s.store.APIKeys().Create(r.Context(), in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createAPIKeyResponse{APIKey: out, Token: mat.Plaintext})
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	id := chi.URLParam(r, "id")
	key, err := s.store.APIKeys().Get(r.Context(), p.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	key.Revoked = true
	out, err := s.store.APIKeys().Update(r.Context(), key)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

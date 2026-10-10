package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/sentinel-iam/sentinel/internal/auth"
	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/store"
)

type createUserRequest struct {
	Email    string       `json:"email"`
	Name     string       `json:"name"`
	Password string       `json:"password"`
	Role     model.Role   `json:"role"`
	Status   model.Status `json:"status"`
}

type updateUserRequest struct {
	Name     string       `json:"name"`
	Password string       `json:"password"`
	Role     model.Role   `json:"role"`
	Status   model.Status `json:"status"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	q := r.URL.Query()
	limit, offset := s.page(r)
	f := store.UserFilter{
		Role:   model.Role(q.Get("role")),
		Status: model.Status(q.Get("status")),
		Query:  q.Get("q"),
		Limit:  limit,
		Offset: offset,
	}
	users, total, err := s.store.Users().List(r.Context(), p.TenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, users, total, limit, offset)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	if err := model.ValidatePassword(req.Password); err != nil {
		writeError(w, err)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, err)
		return
	}
	role := req.Role
	if role == "" {
		role = model.RoleViewer
	}
	status := req.Status
	if status == "" {
		status = model.StatusActive
	}
	in := model.User{
		TenantID:     p.TenantID,
		Email:        strings.TrimSpace(req.Email),
		Name:         req.Name,
		PasswordHash: hash,
		Role:         role,
		Status:       status,
	}
	out, err := s.store.Users().Create(r.Context(), in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	out, err := s.store.Users().Get(r.Context(), p.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	id := chi.URLParam(r, "id")
	existing, err := s.store.Users().Get(r.Context(), p.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	var req updateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		existing.Name = req.Name
	}
	if req.Role != "" {
		existing.Role = req.Role
	}
	if req.Status != "" {
		existing.Status = req.Status
	}
	if req.Password != "" {
		if err := model.ValidatePassword(req.Password); err != nil {
			writeError(w, err)
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			writeError(w, err)
			return
		}
		existing.PasswordHash = hash
	}
	out, err := s.store.Users().Update(r.Context(), existing)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	if err := s.store.Users().Delete(r.Context(), p.TenantID, chi.URLParam(r, "id")); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

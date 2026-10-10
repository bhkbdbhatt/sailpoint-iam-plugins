package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sentinel-iam/sentinel/internal/auth"
	"github.com/sentinel-iam/sentinel/internal/model"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string     `json:"token"`
	ExpiresAt time.Time  `json:"expires_at"`
	User      model.User `json:"user"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.loginGuard.allow("ip:" + ip) {
		s.log.Warn("login rate limit exceeded", "ip", ip)
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: errorBody{Code: "rate_limited", Message: "too many login attempts; try again later"}})
		return
	}
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Code: "invalid_input", Message: "invalid request body"}})
		return
	}
	emailKey := "email:" + strings.ToLower(strings.TrimSpace(req.Email))
	if !s.loginGuard.allow(emailKey) {
		s.log.Warn("login rate limit exceeded", "email", req.Email)
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: errorBody{Code: "rate_limited", Message: "too many login attempts; try again later"}})
		return
	}
	user, err := s.store.Users().GetByEmail(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "invalid credentials"}})
			return
		}
		writeError(w, err)
		return
	}
	if user.Status != model.StatusActive {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: errorBody{Code: "forbidden", Message: "account is not active"}})
		return
	}
	ok, err := auth.VerifyPassword(user.PasswordHash, req.Password)
	if err != nil || !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "invalid credentials"}})
		return
	}
	s.loginGuard.reset(emailKey)
	token, exp, err := s.jwt.Issue(user.ID, user.TenantID, string(user.Role), user.Email, "password")
	if err != nil {
		writeError(w, err)
		return
	}
	now := time.Now().UTC()
	user.LastLoginAt = &now
	if _, err := s.store.Users().Update(r.Context(), user); err != nil {
		s.log.Warn("failed to update last login", "user_id", user.ID, "error", err)
	}
	writeJSON(w, http.StatusOK, loginResponse{Token: token, ExpiresAt: exp, User: user})
}

type meResponse struct {
	User        model.User `json:"user"`
	Permissions []string   `json:"permissions"`
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	user, err := s.store.Users().Get(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, meResponse{User: user, Permissions: auth.Permissions(p.Role)})
}

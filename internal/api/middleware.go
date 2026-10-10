package api

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sentinel-iam/sentinel/internal/auth"
	"github.com/sentinel-iam/sentinel/internal/model"
)

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token := bearerToken(r); token != "" {
			claims, err := s.jwt.Parse(token)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "invalid or expired token"}})
				return
			}
			role := model.Role(claims.Role)
			if !role.Valid() {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "token has invalid role"}})
				return
			}
			p := principal{UserID: claims.Subject, TenantID: claims.TenantID, Role: role, Email: claims.Email, Method: "jwt"}
			next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
			return
		}

		if key := r.Header.Get("X-API-Key"); key != "" {
			if err := auth.ValidateAPIKeyFormat(key); err != nil {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "invalid api key"}})
				return
			}
			rec, err := s.store.APIKeys().GetByHash(r.Context(), auth.HashAPIKey(key))
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "invalid api key"}})
				return
			}
			if rec.Revoked {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "api key revoked"}})
				return
			}
			if rec.ExpiresAt != nil && rec.ExpiresAt.Before(time.Now().UTC()) {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "api key expired"}})
				return
			}
			if !rec.Role.Valid() {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "api key has invalid role"}})
				return
			}
			p := principal{UserID: rec.UserID, TenantID: rec.TenantID, Role: rec.Role, Method: "api_key"}
			next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
			return
		}

		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "authentication required"}})
	})
}

func (s *Server) requirePerm(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := principalFrom(r.Context())
			if !ok {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: errorBody{Code: "unauthorized", Message: "authentication required"}})
				return
			}
			if !auth.Can(p.Role, perm) {
				writeJSON(w, http.StatusForbidden, errorResponse{Error: errorBody{Code: "forbidden", Message: "missing permission " + perm}})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// clientIP returns the immediate peer address, without trusting any
// client-supplied forwarding headers.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

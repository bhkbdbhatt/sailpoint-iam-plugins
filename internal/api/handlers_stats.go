package api

import "net/http"

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	ov, err := s.store.Stats().Overview(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

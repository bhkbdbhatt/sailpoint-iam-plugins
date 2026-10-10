package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/sentinel-iam/sentinel/internal/model"
)

type fieldError struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

type errorBody struct {
	Code    string       `json:"code"`
	Message string       `json:"message"`
	Fields  []fieldError `json:"fields,omitempty"`
}

type errorResponse struct {
	Error errorBody `json:"error"`
}

type listResponse struct {
	Data   any `json:"data"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func writeList(w http.ResponseWriter, data any, total, limit, offset int) {
	writeJSON(w, http.StatusOK, listResponse{Data: data, Total: total, Limit: limit, Offset: offset})
}

func writeError(w http.ResponseWriter, err error) {
	status, body := errorFor(err)
	writeJSON(w, status, errorResponse{Error: body})
}

func errorFor(err error) (int, errorBody) {
	var verrs model.ValidationErrors
	if errors.As(err, &verrs) {
		fields := make([]fieldError, 0, len(verrs))
		for _, fe := range verrs {
			fields = append(fields, fieldError{Field: fe.Field, Reason: fe.Reason})
		}
		code, msg := statusFor(err)
		return code, errorBody{Code: "validation_error", Message: msg, Fields: fields}
	}
	var fe *model.FieldError
	if errors.As(err, &fe) {
		return http.StatusBadRequest, errorBody{
			Code:    "validation_error",
			Message: "invalid input",
			Fields:  []fieldError{{Field: fe.Field, Reason: fe.Reason}},
		}
	}
	code, msg := statusFor(err)
	return code, errorBody{Code: codeName(err), Message: msg}
}

func statusFor(err error) (int, string) {
	switch {
	case errors.Is(err, model.ErrNotFound):
		return http.StatusNotFound, "not found"
	case errors.Is(err, model.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, model.ErrUnauthorized):
		return http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, model.ErrForbidden):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, model.ErrInvalid):
		return http.StatusBadRequest, "invalid input"
	default:
		return http.StatusBadRequest, err.Error()
	}
}

func codeName(err error) string {
	switch {
	case errors.Is(err, model.ErrNotFound):
		return "not_found"
	case errors.Is(err, model.ErrConflict):
		return "conflict"
	case errors.Is(err, model.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, model.ErrForbidden):
		return "forbidden"
	case errors.Is(err, model.ErrInvalid):
		return "invalid_input"
	default:
		return "bad_request"
	}
}

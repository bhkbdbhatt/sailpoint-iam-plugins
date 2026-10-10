package model

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrInvalid      = errors.New("invalid input")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

type FieldError struct {
	Field  string
	Reason string
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}

func (e *FieldError) Unwrap() error { return ErrInvalid }

type ValidationErrors []*FieldError

func (v ValidationErrors) Error() string {
	if len(v) == 0 {
		return "invalid input"
	}
	s := v[0].Error()
	for _, e := range v[1:] {
		s += "; " + e.Error()
	}
	return s
}

func (v ValidationErrors) Unwrap() error { return ErrInvalid }

func field(field, reason string) *FieldError {
	return &FieldError{Field: field, Reason: reason}
}

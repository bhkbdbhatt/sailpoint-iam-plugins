// Package openapi embeds the Sentinel OpenAPI 3.1 specification so the server
// can expose it and its bundled documentation UI without external files.
package openapi

import _ "embed"

// Spec is the canonical OpenAPI 3.1 document served at /openapi.yaml.
//
//go:embed openapi.yaml
var Spec []byte

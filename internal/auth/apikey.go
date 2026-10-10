package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const APIKeyPrefix = "snl_"

type APIKeyMaterial struct {
	Plaintext string
	Prefix    string
	Hash      string
}

func GenerateAPIKey() (*APIKeyMaterial, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	plaintext := APIKeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return &APIKeyMaterial{
		Plaintext: plaintext,
		Prefix:    plaintext[:len(APIKeyPrefix)+6],
		Hash:      HashAPIKey(plaintext),
	}, nil
}

func HashAPIKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func IsAPIKeyToken(token string) bool {
	return len(token) > len(APIKeyPrefix) && subtle.ConstantTimeCompare([]byte(token[:len(APIKeyPrefix)]), []byte(APIKeyPrefix)) == 1
}

func ValidateAPIKeyFormat(token string) error {
	if !IsAPIKeyToken(token) {
		return fmt.Errorf("invalid api key format")
	}
	if len(token) < len(APIKeyPrefix)+32 {
		return fmt.Errorf("api key too short")
	}
	return nil
}

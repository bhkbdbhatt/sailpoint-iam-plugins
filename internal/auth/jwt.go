package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwt.RegisteredClaims
	TenantID   string `json:"tid"`
	Role       string `json:"role"`
	Email      string `json:"email"`
	AuthMethod string `json:"am"`
}

type JWTManager struct {
	key    *rsa.PrivateKey
	issuer string
	ttl    time.Duration
}

func LoadOrCreateJWTManager(keyPath, issuer string, ttl time.Duration) (*JWTManager, error) {
	key, err := loadOrCreateRSAKey(keyPath)
	if err != nil {
		return nil, err
	}
	return &JWTManager{key: key, issuer: issuer, ttl: ttl}, nil
}

func NewJWTManagerFromKey(key *rsa.PrivateKey, issuer string, ttl time.Duration) *JWTManager {
	return &JWTManager{key: key, issuer: issuer, ttl: ttl}
}

func (m *JWTManager) Issue(userID, tenantID, role, email, method string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(m.ttl)
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, err
	}
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			NotBefore: jwt.NewNumericDate(now),
			ID:        fmt.Sprintf("%x", jti),
		},
		TenantID:   tenantID,
		Role:       role,
		Email:      email,
		AuthMethod: method,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(m.key)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

func (m *JWTManager) Parse(token string) (*Claims, error) {
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &m.key.PublicKey, nil
	}, jwt.WithIssuer(m.issuer), jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func (m *JWTManager) TTL() time.Duration { return m.ttl }

func loadOrCreateRSAKey(path string) (*rsa.PrivateKey, error) {
	encoded, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(encoded)
		if block == nil {
			return nil, fmt.Errorf("no PEM block in %s", path)
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read jwt key: %w", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	encoded = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	return key, nil
}

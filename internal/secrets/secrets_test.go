package secrets

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	box, err := NewFromKey(key)
	if err != nil {
		t.Fatalf("new box: %v", err)
	}
	enc, err := box.Encrypt("sk-123-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc == "sk-123-secret" || enc == "" {
		t.Fatalf("encrypt produced %q", enc)
	}
	dec, err := box.Decrypt(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if dec != "sk-123-secret" {
		t.Fatalf("round trip mismatch: %q", dec)
	}
	// Deterministic? No: two encryptions must differ (random nonce).
	enc2, _ := box.Encrypt("sk-123-secret")
	if enc == enc2 {
		t.Fatal("ciphertexts identical, nonce not random")
	}
	// Wrong key fails to decrypt.
	other := make([]byte, 32)
	if _, err := rand.Read(other); err != nil {
		t.Fatal(err)
	}
	otherBox, _ := NewFromKey(other)
	if _, err := otherBox.Decrypt(enc); err == nil {
		t.Fatal("decrypt with wrong key succeeded")
	}
	// Garbage ciphertext fails.
	if _, err := box.Decrypt("not-base64-!"); err == nil {
		t.Fatal("decrypt garbage succeeded")
	}
	// Empty plaintext encrypts and decrypts.
	emp, err := box.Encrypt("")
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	if got, err := box.Decrypt(emp); err != nil || got != "" {
		t.Fatalf("empty round trip: %q %v", got, err)
	}
}

func TestLoadOrCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")

	b1, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("load or create: %v", err)
	}
	if b1 == nil {
		t.Fatal("nil box")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty key file")
	}
	// Second load reads the same key: ciphertext compatibility.
	b2, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	enc, err := b1.Encrypt("token")
	if err != nil {
		t.Fatal(err)
	}
	if dec, err := b2.Decrypt(enc); err != nil || dec != "token" {
		t.Fatalf("cross-load decrypt: %q %v", dec, err)
	}
}

func TestNewFromKeyRejectsShortKey(t *testing.T) {
	if _, err := NewFromKey([]byte("tooshort")); err == nil {
		t.Fatal("short key accepted")
	}
}

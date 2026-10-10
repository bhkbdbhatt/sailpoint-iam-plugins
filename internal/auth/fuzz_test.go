package auth

import "testing"

func FuzzVerifyPassword(f *testing.F) {
	f.Add("argon2id$v=19$m=131072,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$c2FsdHNhbHRzYWx0", "supersecret123")
	f.Add("not-a-hash", "")
	f.Add("", "")
	f.Add("argon2id$v=19$m=131072,t=3,p=4$$", "x")

	f.Fuzz(func(t *testing.T, encoded, password string) {
		_, _ = VerifyPassword(encoded, password)
	})
}

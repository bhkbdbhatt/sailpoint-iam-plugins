package store

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzFileSnapshotLoad(f *testing.F) {
	seed := `{"version":1,"identities":{"id1":{"id":"id1","tenant_id":"t","type":"human","name":"A"}},"users":{"u1":{"id":"u1","email":"a@example.com","password_hash":"h"}},"api_keys":{"k1":{"id":"k1","prefix":"sk","hash":"hh"}}}`
	f.Add([]byte(seed))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"identities":{"x":{"id":"x"}}}`))
	f.Add([]byte(`{"tenants":{"t":{"slug":"a"}}}`))
	f.Add([]byte(`garbage`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "store.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		m, err := NewFile(path)
		if err != nil {
			return
		}
		m.rebuildIndexes()
	})
}

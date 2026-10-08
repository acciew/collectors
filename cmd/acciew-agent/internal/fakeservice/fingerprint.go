package fakeservice

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	h := hex.EncodeToString(sum[:16])
	groups := make([]string, 8)
	for i := range groups {
		groups[i] = h[i*4 : i*4+4]
	}
	return strings.Join(groups, "-")
}

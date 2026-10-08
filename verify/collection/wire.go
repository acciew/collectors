package collection

import (
	"strconv"
	"time"

	"go.acciew.io/collector/verify/chain"
)

// Entry is one line of a collection log: where it sits in the chain, and the run.
type Entry struct {
	chain.Entry
	Run Run `json:"run"`
}

// Run is one collection, recorded whole. The JSON tags are the format of a line;
// the digest is taken over a separate canonical rendering (see Canonical).
type Run struct {
	Source    string    `json:"source"`
	StartedAt time.Time `json:"started_at"`
	Whole     bool      `json:"whole"`
	// Verdict and Cause are enumerations, written as their numbers. A number
	// this verifier has no name for is still a number, and is hashed as one.
	Verdict  int32   `json:"verdict"`
	Cause    int32   `json:"cause"`
	Scopes   []Scope `json:"scopes"`
	Counts   Counts  `json:"counts"`
	Observed []Grant `json:"observed"`
}

// Scope is what happened to one isolation boundary.
type Scope struct {
	ID                   string `json:"id"`
	Status               int32  `json:"status"`
	Reason               string `json:"reason,omitempty"`
	ActivityAvailable    bool   `json:"activity_available"`
	ActivityUndetermined bool   `json:"activity_undetermined,omitempty"`
}

// Counts are the population sizes, kept beside the observations.
type Counts struct {
	Identities   int64 `json:"identities"`
	Groupings    int64 `json:"groupings"`
	Entitlements int64 `json:"entitlements"`
	Resources    int64 `json:"resources"`
	Grants       int64 `json:"grants"`
	Referenced   int64 `json:"referenced"`
}

// Grant is one subject holding one entitlement by one route.
type Grant struct {
	Identity    Key   `json:"identity"`
	Entitlement Key   `json:"entitlement"`
	Fidelity    int32 `json:"fidelity"`
	Via         []Key `json:"via,omitempty"`
}

// Key names a node: the isolation boundary it was seen in, its type, and the
// source's own identifier for it.
type Key struct {
	Scope string `json:"scope"`
	Type  int32  `json:"type"`
	ID    string `json:"id"`
}

// String renders a key as "<scope>/<type name>/<id>", with nothing escaped. The
// canonical form hashes keys in this rendering.
func (k Key) String() string { return k.Scope + "/" + typeName(k.Type) + "/" + k.ID }

// typeName is the word for a node type. Zero is never a real type, and a number
// without a name here is written as such; naming a sixth type is a new format.
func typeName(t int32) string {
	switch t {
	case 1:
		return "identity"
	case 2:
		return "grouping"
	case 3:
		return "entitlement"
	case 4:
		return "resource"
	case 5:
		return "scope"
	case 0:
		return "unspecified"
	}
	return "unrecognised(" + strconv.FormatInt(int64(t), 10) + ")"
}

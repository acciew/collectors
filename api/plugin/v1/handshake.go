package pluginv1

import "strconv"

// Handshake constants, shared by the host and by every plugin.
//
// They live in the contract module rather than in the SDK because both sides
// need them and neither may depend on the other: the core cannot import the
// SDK, and a plugin must not import the core. They are plain values rather
// than a transport library's config type, so this module stays free of any
// transport dependency and the values survive ADR-0002 being revisited.

const (
	// MagicCookieKey and MagicCookieValue are a mutual check that a launched
	// binary is an Acciew plugin and not something else that happens to be
	// executable. They are not a security boundary and are not secret.
	MagicCookieKey   = "ACCIEW_PLUGIN"
	MagicCookieValue = "acciew-plugin-v1"

	// MechanismVersion versions the plugin *mechanism* — how a process is
	// launched and how it is asked what it is. It is deliberately separate
	// from any kind's contract version, and changes only if the mechanism
	// itself breaks.
	MechanismVersion = 1

	// HandshakeEntry is where the kind-agnostic handshake is served. Every
	// plugin binary offers it, whatever else it does.
	HandshakeEntry = "handshake"
)

// Entry names where a kind's contract is served, e.g. "collector/1".
//
// The kind and its version are in the name, so adding a notifier or an
// exporter later is a new entry rather than a new mechanism.
func Entry(kind string, protocolVersion uint32) string {
	return kind + "/" + strconv.FormatUint(uint64(protocolVersion), 10)
}

//go:build !unix

package state

// Lock does nothing where there is no flock; the agent is released for Linux and macOS.
func Lock(string) (unlock func(), err error) { return func() {}, nil }

// LockRotation is as Lock.
func LockRotation(string) (unlock func(), err error) { return func() {}, nil }

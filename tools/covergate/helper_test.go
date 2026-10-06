package main

import "os"

func writeGates(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

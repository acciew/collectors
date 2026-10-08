//go:build !unix

package pathid

// tagOf names a directory by its path where there are no inode numbers to read.
func tagOf(dir string) string { return fallbackTag(dir) }

package secrets

// Held is how many bytes of earlier events the scanner keeps to join to the next ones.
func (s *Scanner) Held() int {
	n := 0
	for _, t := range s.tails {
		n += len(t.data)
	}
	return n
}

// Work is how many bytes the scanner has looked at, over and above the bytes of the events themselves.
func (s *Scanner) Work() int { return s.work }

// Open is how many places in what is kept the scanner is following as the start of a pattern.
func (s *Scanner) Open() int {
	n := 0
	for _, t := range s.tails {
		n += len(t.open)
	}
	return n
}

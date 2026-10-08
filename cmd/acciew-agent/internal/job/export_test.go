package job

// Spend is for the tests of the account, which would otherwise need hundreds of runs.
func (r *Runner) Spend(run string, n int64) { r.spend(run, n) }

// Accounts is how many runs have an account.
func (r *Runner) Accounts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.spent)
}

// CleanReason is the last step a reason takes before it is sent.
var CleanReason = scrub

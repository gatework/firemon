package design

// Script is a plan rendered as device commands. Commands configure the
// change; Rollback undoes it and is shown to operators, never sent
// automatically. Both exclude entering and leaving configuration mode and
// saving or committing, which deployment performs.
type Script struct {
	Commands []string `json:"commands"`
	Rollback []string `json:"rollback"`
}

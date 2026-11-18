package firemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Fingerprint returns a digest of the policy-relevant configuration: every
// field of Config except diagnostics. Two configurations with the same
// fingerprint compile to the same firewall. Design plans record it as their
// baseline so deployment can detect configuration drift.
func (fw *Firewall) Fingerprint() string { return fw.fingerprint }

func fingerprint(cfg *Config) string {
	c := *cfg
	c.Diagnostics = nil
	raw, err := json.Marshal(&c)
	if err != nil {
		// Config holds only marshalable values; failure is a programming defect.
		panic("firemon: fingerprint: " + err.Error())
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

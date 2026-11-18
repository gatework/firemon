// Package filestore keeps the latest configuration snapshot of each device
// in a directory, so firewalls can be queried, audited and designed on
// without contacting the device or re-parsing its configuration.
//
// Layout: <root>/<device>/raw.txt (the collected text), config.json (the
// parsed firemon.Config) and meta.json (vendor, host, collection time and
// fingerprint). Every file is written atomically and meta.json is written
// last, so a snapshot is complete when its metadata exists. Loading checks
// that the stored configuration still compiles to the recorded fingerprint.
package filestore

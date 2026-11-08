# Releasing Firemon

Firemon ships Go source modules. The root module uses `vX.Y.Z`; the optional
connector uses `adapter/netconnector/vX.Y.Z`. Releases have no precompiled CLI
assets. Keep the repository visibility unchanged during publication.

## Source and verification

1. Resolve the latest published tags, fetch the remote, and account for staged,
   modified and untracked files. Preserve other worktrees and unrelated changes.
2. Record the intended source hashes and review the release range. Update the
   changelog and installation examples, including intentional API breaks and
   known capability refusals.
3. Verify the exact candidate in an isolated checkout: formatting, module
   manifests, build, vet and uncached race tests. Exercise the installed CLI and
   check the module archive includes new helpers and contains no production
   captures, credentials, local caches or private dependency source.
4. Commit only the recorded paths and push without rewriting remote history.
   All required CI jobs must succeed for that exact commit before tagging.

The existing CI matrix checks Go 1.27.0 and 1.27.x for the core, the adapter's
published dependency pin, and the adapter paired with the current core. These
are separate checks; workspace success does not prove a versioned consumer.

## Publish in dependency order

1. Tag the verified core commit and create a draft GitHub Release with the existing
   `Firemon Go vX.Y.Z` title convention.
2. In a fresh module cache, download the core through the public Go proxy and
   checksum database with `GOWORK=off` and no replacement. Build an independent
   consumer, run `go mod verify`, install `cmd/firemon`, and inspect its help and
   embedded module version. Compare the module ZIP files byte-for-byte with the
   tagged source, applying Go module ZIP exclusions for nested modules and VCS
   metadata. Publish the draft only after these checks pass.
3. Update the adapter to the published core version, run `go mod tidy`, and
   verify it independently with `GOWORK=off`. Commit and push that pin, wait for
   the exact-commit CI, then publish its nested-module tag and create a draft Release.
4. Download and verify the adapter with another fresh consumer and compare its
   module ZIP with its tagged source before publishing that draft. Release notes
   link the successful CI and record the verified module checksums.

After any timeout, read back tags and Release state before retrying a write.
Never move a published tag or republish an uncertain upload. At completion,
record the remote commit, tags, public Release state, module checksums and local
worktree state. Local/CI/module verification does not establish real-device or
unrestricted native-firmware compatibility.

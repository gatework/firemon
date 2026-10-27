# Optional device connector adapter

This separate module implements `deploy.Factory` and `deploy.Session` using the private `github.com/gatework/go-net-connector` module. The root firemon module remains independent of it. Dependency versions refer to published Git commits; no local `replace` directives or private dependency source are included here.

The host supplies device identity, credentials and connection options through `Factory.Resolve`. `Factory.Open` constructs a fresh connector device on every call, including independent readback and recovery. It applies bounded capture limits and uses connector's Hillstone/PAN profiles or the ASA profile supplied here. `New` also accepts a host-owned device and transfers its ownership on success; callers using it directly must configure the device's transport limits and validated profile themselves.

`Execute` writes each confirmed command receipt before sending the next command. A partial write or rejected command retains uncertain progress when available. Receipt errors, cancellation, connection errors and unconfirmed persistence retire the session. `Close` interrupts active I/O and commit polling; an observer cannot reenter a busy session. There is no command retry or automatic reconnect.

`Save` uses affirmative persistence evidence:

- Hillstone uses connector's native `save all` validation.
- ASA requires its configuration-building response and a standalone `[OK]`, with no failure in the response history.
- PAN retains the numeric ID returned by `commit` and polls that exact job with a bounded count, cumulative output budget and context deadline. Only a matching `Commit` job with valid `FIN OK` completion evidence produces a durable receipt. Other jobs, failures and malformed results stay uncertain.

Running capture uses connector's native collection workflow, including PAN candidate-diff checks. Persistent capture is separate: ASA `show startup-config`, Hillstone `show configuration startup`, and PAN `show config saved running-config.xml`. PAN persistent capture must contain a complete configuration XML root. Native configuration content remains available to firemon's parser; successful transport does not imply supported semantics.

The module has synthetic `net.Pipe` transcript tests and a complete ASA flow through the native parser, planner, durable journal and snapshot store. The latter covers successful application and independent recovery after a lost save response, including proof that configuration writes are not replayed. These tests are not real-device interoperability evidence.

With authenticated Git access to the private connector repository:

```sh
cd adapter/netconnector
GOWORK=off GOPRIVATE=github.com/gatework/go-net-connector go test -count=1 -race ./...
GOWORK=off GOPRIVATE=github.com/gatework/go-net-connector go vet ./...
GOWORK=off GOPRIVATE=github.com/gatework/go-net-connector go mod verify
```

The public root CI does not have access to that private dependency and does not test this nested module. Native evidence and firmware limits are listed in [the semantics notes](../../docs/native-semantics.md).

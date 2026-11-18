package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/workflow"
)

// Deps are the process resources the commands use.
type Deps struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	Now    func() time.Time
}

// Exit codes.
const (
	ExitOK = iota
	ExitError
	ExitUsage
	// ExitNotAllowed reports a query whose verdict is not allowed, or a plan
	// that is not verified, so scripts can branch on the result.
	ExitNotAllowed
)

// errNotAllowed makes Run return ExitNotAllowed after printing the result.
var errNotAllowed = errors.New("not allowed")

// Run executes the command line and returns the process exit code.
func Run(ctx context.Context, args []string, deps Deps) int {
	root := newRoot(ctx, &deps)
	root.SetArgs(args)
	root.SetIn(deps.Stdin)
	root.SetOut(deps.Stdout)
	root.SetErr(deps.Stderr)
	err := root.Execute()
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, errNotAllowed):
		return ExitNotAllowed
	default:
		fmt.Fprintln(deps.Stderr, "firemon:", err)
		if _, ok := errors.AsType[*usageError](err); ok {
			return ExitUsage
		}
		return ExitError
	}
}

// usageError marks invalid flags or arguments.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// options are the flags shared by every command.
type options struct {
	deps     *Deps
	vendor   string
	file     string
	snapshot string
	store    string
	book     string
	timezone string
	device   deviceFlags
	json     bool
}

func newRoot(ctx context.Context, deps *Deps) *cobra.Command {
	o := &options{deps: deps}
	root := &cobra.Command{
		Use:           "firemon",
		Short:         "Firewall policy query, design and deployment for Hillstone and PAN-OS",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	f := root.PersistentFlags()
	f.StringVar(&o.vendor, "vendor", "", "device vendor: hillstone or paloalto")
	f.StringVar(&o.file, "config", "", "running configuration file (instead of reading the device)")
	f.StringVar(&o.snapshot, "snapshot", "", "use the stored snapshot of this device (see collect)")
	f.StringVar(&o.store, "store", defaultStore(), "snapshot directory")
	f.StringVar(&o.book, "service-book", "", "JSON predefined service book observed on the device, overriding the vendor default (see services)")
	f.StringVar(&o.timezone, "timezone", "Local", "device time zone for schedules (IANA name)")
	f.BoolVar(&o.json, "json", false, "print JSON")
	o.device.register(root)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &usageError{err} })
	root.SetContext(ctx)
	root.AddCommand(newParseCmd(o), newQueryCmd(o), newUsageCmd(o), newDesignCmd(o), newDeployCmd(o), newAuditCmd(o), newCollectCmd(o), newLocateCmd(o), newServicesCmd(o)) //nolint:contextcheck // cobra hands the context to RunE through cmd.Context()
	return root
}

// platform resolves the vendor and time zone flags.
func (o *options) platform() (bootstrap.Platform, error) {
	v, err := firemon.ParseVendor(o.vendor)
	if err != nil {
		return bootstrap.Platform{}, &usageError{err}
	}
	loc, err := time.LoadLocation(o.timezone)
	if err != nil {
		return bootstrap.Platform{}, &usageError{err}
	}
	book, err := o.serviceBook()
	if err != nil {
		return bootstrap.Platform{}, err
	}
	return bootstrap.Lookup(v, loc, book)
}

// load reads the configuration from --config, --snapshot or the device.
func (o *options) load(ctx context.Context) (workflow.Loaded, bootstrap.Platform, error) {
	if o.snapshot != "" {
		return o.loadSnapshot(ctx)
	}
	p, err := o.platform()
	if err != nil {
		return workflow.Loaded{}, p, err
	}
	src := workflow.Source{Platform: p, File: o.file}
	if o.file == "" {
		client, err := o.device.client(p, o.deps.Getenv)
		if err != nil {
			return workflow.Loaded{}, p, err
		}
		src.Device = client
	}
	loaded, err := workflow.Load(ctx, src)
	return loaded, p, err
}

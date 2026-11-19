package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

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
	// ExitNotAllowed reports traffic that is not (fully) allowed; check
	// returns it when every firewall that needs a change has a verified
	// one, ready to deploy.
	ExitNotAllowed
	// ExitUndecided reports a result that needs a person: rules that
	// cannot be evaluated offline, a deny rule the design will not pass
	// without --override, or a change that failed verification.
	ExitUndecided
)

var (
	// errNotAllowed makes Run return ExitNotAllowed after printing the result.
	errNotAllowed = errors.New("not allowed")
	// errUndecided makes Run return ExitUndecided after printing the result.
	errUndecided = errors.New("needs confirmation")
)

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
	case errors.Is(err, errUndecided):
		return ExitUndecided
	default:
		raw := err.Error()
		msg := localizeError(err)
		if !strings.HasPrefix(msg, "firemon") {
			msg = "firemon: " + msg
		}
		fmt.Fprintln(deps.Stderr, msg)
		if _, ok := errors.AsType[*usageError](err); ok || isCobraUsage(raw) {
			return ExitUsage
		}
		return ExitError
	}
}

// isCobraUsage reports the argument errors cobra returns unwrapped.
func isCobraUsage(msg string) bool {
	for _, p := range []string{"unknown command", "accepts ", "requires at ", "invalid argument", "unknown flag", "unknown shorthand flag"} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
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
	// inventoryFile is the YAML operator inventory with protected networks.
	inventoryFile string
	timezone      string
	// logSetting is the log forwarding profile of new rules (settings file).
	logSetting string
	device     deviceFlags
	json       bool
}

func newRoot(ctx context.Context, deps *Deps) *cobra.Command {
	o := &options{deps: deps}
	root := &cobra.Command{
		Use:           "firemon",
		Short:         "防火墙策略查询、设计、收敛、迁移与下发（山石 StoneOS、Palo Alto PAN-OS）",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	f := root.PersistentFlags()
	f.StringVar(&o.vendor, "vendor", "", "设备厂商：hillstone 或 paloalto")
	f.StringVar(&o.file, "config", "", "运行配置文件（代替登录设备读取）")
	f.StringVar(&o.snapshot, "snapshot", "", "使用已保存的该设备快照（见 collect）")
	f.StringVar(&o.store, "store", "", "快照目录（默认依次取 $FIREMON_STORE、库存文件的 store、配置文件、用户配置目录）")
	f.StringVar(&o.inventoryFile, "inventory", "", "库存文件（YAML）：防火墙、HA 集群、快照与受保护网段（默认取 $FIREMON_INVENTORY 或配置文件）")
	f.StringVar(&o.book, "predefined-service", "", "设备上实际的预定义服务表（JSON），覆盖厂商默认值（见 predefined-service 命令）")
	f.StringVar(&o.book, "service-book", "", "同 --predefined-service（旧名）")
	_ = f.MarkHidden("service-book")
	f.StringVar(&o.timezone, "timezone", "", "设备时区，用于时间计划，IANA 名称（默认取 $FIREMON_TIMEZONE、配置文件或本机时区）")
	f.BoolVar(&o.json, "json", false, "输出 JSON")
	o.device.register(root)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &usageError{err} })
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error { return o.resolveDefaults(cmd) }
	root.SetContext(ctx)
	root.AddCommand(newCheckCmd(o), newDeployCmd(o), newCollectCmd(o), newHitsCmd(o), newConvergeCmd(o), newAuditCmd(o), newMigrateCmd(o), newParseCmd(o), newServicesCmd(o), newUsageCmd(o)) //nolint:contextcheck // cobra hands the context to RunE through cmd.Context()
	localizeHelp(root)
	return root
}

// platform resolves the vendor and time zone flags.
func (o *options) platform() (bootstrap.Platform, error) {
	name := o.vendor
	if name == "" && o.file != "" {
		name = detectVendor(o.file) // a configuration says which vendor wrote it
	}
	v, err := vendor("--vendor", name)
	if err != nil {
		return bootstrap.Platform{}, err
	}
	loc, err := time.LoadLocation(o.timezone)
	if err != nil {
		return bootstrap.Platform{}, &usageError{fmt.Errorf("--timezone %q 不是有效的时区：请用 IANA 名称，例如 Asia/Shanghai", o.timezone)}
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

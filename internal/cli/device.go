package cli

import (
	"errors"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/internal/bootstrap"
)

// Environment variables holding credentials; credentials are never flags.
const (
	envPassword = "FIREMON_PASSWORD"
	envEnable   = "FIREMON_ENABLE_PASSWORD"
)

// deviceFlags select the device to read or change.
type deviceFlags struct {
	host       string
	user       string
	port       int
	knownHosts string
	timeout    time.Duration
}

func (d *deviceFlags) register(cmd *cobra.Command) {
	f := cmd.PersistentFlags()
	f.StringVar(&d.host, "host", "", "设备地址")
	f.StringVar(&d.user, "user", "", "登录用户；密码从环境变量 "+envPassword+" 读取")
	f.IntVar(&d.port, "port", 22, "设备 SSH 端口")
	f.StringVar(&d.knownHosts, "known-hosts", "", "SSH known_hosts 文件（默认使用当前用户的）")
	f.DurationVar(&d.timeout, "command-timeout", 2*time.Minute, "单条设备命令的超时时间")
}

func (d *deviceFlags) client(p bootstrap.Platform, getenv func(string) string) (*netconnector.Client, error) {
	if d.host == "" || d.user == "" {
		return nil, &usageError{errors.New("请用 --config 指定配置文件，或用 --host 和 --user 登录设备读取")}
	}
	return netconnector.NewSSH(p.Vendor, netconnector.SSHConfig{
		Host: d.host, Username: d.user, Password: getenv(envPassword), EnablePassword: getenv(envEnable),
		Port: d.port, KnownHosts: d.knownHosts, CommandTimeout: d.timeout,
	}, p.Parse)
}

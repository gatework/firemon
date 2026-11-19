package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/intake"
)

// vendor parses a vendor flag with a Chinese error that says what to set.
func vendor(flag, value string) (firemon.Vendor, error) {
	v, err := firemon.ParseVendor(value)
	switch {
	case err == nil:
		return v, nil
	case value == "":
		return v, &usageError{fmt.Errorf("需要 %s 指定厂商：hillstone 或 paloalto", flag)}
	default:
		return v, &usageError{fmt.Errorf("%s %q 不是已支持的厂商：可选 hillstone 或 paloalto", flag, value)}
	}
}

// snapshotError explains a snapshot that cannot be loaded.
func snapshotError(err error, name, store string) error {
	if errors.Is(err, filestore.ErrNotFound) {
		return &usageError{fmt.Errorf("快照 %s 不存在（快照目录 %s）：先用 firemon collect --name %s 保存，或用 --store 指定快照目录", name, store, name)}
	}
	return fmt.Errorf("读取快照 %s 失败：%w", name, err)
}

// inventoryError explains an inventory file that cannot be read.
func inventoryError(err error, path string) error {
	if errors.Is(err, fs.ErrNotExist) {
		return &usageError{fmt.Errorf("找不到库存文件 %s：用 --inventory 指定，或设置环境变量 FIREMON_INVENTORY", path)}
	}
	return &usageError{fmt.Errorf("库存文件 %s 有误：%w", path, err)}
}

// cobraErrors translate the argument errors cobra returns in English.
var cobraErrors = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`unknown command "([^"]*)" for "([^"]*)"`), `未知命令 "$1"（用 "$2 --help" 查看可用命令）`},
	{regexp.MustCompile(`\n\nDid you mean this\?\n`), "\n\n你是不是要用：\n"},
	{regexp.MustCompile(`unknown flag: (\S+)`), "未知参数：$1"},
	{regexp.MustCompile(`unknown shorthand flag: '(.)' in (\S+)`), "未知参数：-$1（$2）"},
	{regexp.MustCompile(`flag needs an argument: (\S+)`), "参数 $1 需要一个值"},
	{regexp.MustCompile(`invalid argument "([^"]*)" for "([^"]*)" flag: .*`), "参数 $2 的值 \"$1\" 无效"},
	{regexp.MustCompile(`accepts 0 arg\(s\), received \d+`), "不接受位置参数，请用 --参数名 值 的形式输入"},
	{regexp.MustCompile(`accepts at most (\d+) arg\(s\), received (\d+)`), "最多接受 $1 个位置参数，实际给了 $2 个"},
}

// localizeError writes an error for the operator: cobra's argument errors
// and file errors in Chinese, everything else as it is.
func localizeError(err error) string {
	switch {
	case errors.Is(err, intake.ErrNoSource):
		return "源地址无法识别：请写 IP、网段、范围或 IP+掩码"
	case errors.Is(err, intake.ErrNoDestination):
		return "目的地址无法识别：请写 IP、网段、范围、IP+掩码或域名"
	case errors.Is(err, intake.ErrNoService):
		return "服务无法识别：请写端口（443）、协议/端口（tcp/80、udp 53）、服务名（https）或 app:应用名"
	}
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "找不到文件 " + pe.Path
		case errors.Is(err, fs.ErrPermission):
			return "没有权限读取 " + pe.Path
		}
	}
	msg := err.Error()
	for _, c := range cobraErrors {
		msg = c.re.ReplaceAllString(msg, c.repl)
	}
	return msg
}

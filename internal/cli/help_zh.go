package cli

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

// usageTemplate is cobra's usage template in Chinese.
const usageTemplate = `用法：{{if .Runnable}}
  {{.UseLine | zhUse}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [命令]{{end}}{{if gt (len .Aliases) 0}}

别名：
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

示例：
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

可用命令：{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

其他命令：{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

参数：
{{.LocalFlags.FlagUsages | zhFlags | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

全局参数：
{{.InheritedFlags.FlagUsages | zhFlags | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

其他帮助主题：{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

用 "{{.CommandPath}} [命令] --help" 查看命令的详细说明。{{end}}
`

// registerTemplateFuncs adds the template functions once: cobra keeps
// them in a package-level map.
var registerTemplateFuncs = sync.OnceFunc(func() {
	cobra.AddTemplateFunc("zhFlags", zhFlags)
	cobra.AddTemplateFunc("zhUse", func(s string) string { return strings.ReplaceAll(s, "[flags]", "[参数]") })
})

// localizeHelp makes the generated help, the help flag and the built-in
// help and completion commands read in Chinese.
func localizeHelp(root *cobra.Command) {
	registerTemplateFuncs()
	root.SetUsageTemplate(usageTemplate)
	groupCommands(root)
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		c.InitDefaultHelpFlag()
		if f := c.Flags().Lookup("help"); f != nil {
			f.Usage = "显示帮助"
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	defer walk(root) // after the help and completion commands below exist
	root.SetHelpCommand(&cobra.Command{
		Use:   "help [命令]",
		Short: "显示任一命令的帮助",
		Run: func(c *cobra.Command, args []string) {
			cmd, _, err := c.Root().Find(args)
			if cmd == nil || err != nil {
				c.Printf("未知的帮助主题 %q\n", args)
				_ = c.Root().Usage()
				return
			}
			cmd.InitDefaultHelpFlag()
			_ = cmd.Help()
		},
	})
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(&cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "生成 shell 自动补全脚本",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			switch args[0] {
			case "bash":
				return c.Root().GenBashCompletionV2(out, true)
			case "zsh":
				return c.Root().GenZshCompletion(out)
			case "fish":
				return c.Root().GenFishCompletion(out, true)
			case "powershell":
				return c.Root().GenPowerShellCompletionWithDesc(out)
			default:
				return &usageError{errUnknownShell}
			}
		},
	})
}

// flagDefault matches the default value pflag appends to a flag's usage.
var flagDefault = regexp.MustCompile(` \(default (.*)\)$`)

// zhFlags rewrites pflag's "(default X)" and value type names.
func zhFlags(usages string) string {
	lines := strings.Split(usages, "\n")
	for i, l := range lines {
		l = strings.Replace(l, " (default true)", "（默认开启）", 1)
		l = flagDefault.ReplaceAllString(l, "（默认 $1）")
		l = strings.Replace(l, "[=true|false]", "             ", 1) // keep the columns
		lines[i] = l
	}
	return strings.Join(lines, "\n")
}

var errUnknownShell = errors.New("不支持的 shell，可选 bash、zsh、fish、powershell")

// commandGroups arranges the commands by what operators do with them.
var commandGroups = []struct {
	group    cobra.Group
	commands []string
}{
	{cobra.Group{ID: "daily", Title: "日常：查询、设计与下发"}, []string{"check", "deploy"}},
	{cobra.Group{ID: "collect", Title: "采集：配置快照与命中计数"}, []string{"collect", "hits"}},
	{cobra.Group{ID: "govern", Title: "治理：收敛、审计与迁移"}, []string{"converge", "audit", "migrate"}},
	{cobra.Group{ID: "tools", Title: "排查工具"}, []string{"parse", "services", "usage"}},
}

func groupCommands(root *cobra.Command) {
	for _, g := range commandGroups {
		root.AddGroup(&g.group)
		for _, c := range root.Commands() {
			if slices.Contains(g.commands, c.Name()) {
				c.GroupID = g.group.ID
			}
		}
	}
}

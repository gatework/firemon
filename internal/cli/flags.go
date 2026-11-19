package cli

import (
	"errors"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/intake"
	"github.com/gatework/firemon/traffic"
)

// trafficFlags describe the traffic a query or intent is about.
type trafficFlags struct {
	src, dst, service string
	fromZone, toZone  string
	vr                string
	at                string
}

func (t *trafficFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&t.src, "src", "", "源地址：10.0.0.1、10.0.0.0/24、10.0.0.1-10.0.0.9、any，逗号分隔")
	f.StringVar(&t.dst, "dst", "", "目的地址，写法同 --src")
	f.StringVar(&t.service, "service", "", "服务：tcp/443、udp/53、tcp/8000-8010、icmp、any，逗号分隔")
	f.StringVar(&t.fromZone, "from-zone", "", "源区域（默认按路由确定）")
	f.StringVar(&t.toZone, "to-zone", "", "目的区域（默认按路由确定）")
	f.StringVar(&t.vr, "virtual-router", "", "虚拟路由器（默认使用厂商默认值）")
	f.StringVar(&t.at, "at", "", "按该时刻（RFC 3339）判断时间计划（默认当前时间）")
}

// parsed is the validated traffic.
type parsed struct {
	src, dst traffic.AddressSet
	domains  []string
	apps     []string
	service  traffic.ServiceSet
	at       time.Time
}

// parse reads the traffic flags tolerantly (see intake); service names are
// read with the given book.
func (t *trafficFlags) parse(book firemon.ServiceBook) (parsed, error) {
	var p parsed
	if t.src == "" || t.dst == "" || t.service == "" {
		return p, &usageError{errors.New("需要 --src 源地址、--dst 目的地址和 --service 服务")}
	}
	in, err := intake.Parse(t.src, t.dst, t.service, intake.Options{Services: book})
	if err != nil {
		return p, &usageError{err}
	}
	p.src, p.dst, p.domains, p.apps, p.service = in.Src, in.Dst, in.DstDomains, in.Applications, in.Service
	if t.at != "" {
		if p.at, err = time.Parse(time.RFC3339, t.at); err != nil {
			return p, &usageError{err}
		}
	}
	return p, nil
}

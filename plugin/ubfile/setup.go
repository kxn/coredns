package ubfile

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("ubfile")

func init() { plugin.Register("ubfile", setup) }

func setup(c *caddy.Controller) error {
	u := UBFile{}
	i := 0
	for c.Next() {
		if i > 0 {
			return plugin.ErrOnce
		}
		i++
		var filename string
		if !c.Args(&filename) {
			return c.ArgErr()
		}
		data, err := LoadUBFile(filename)
		if err != nil {
			return err
		}
		u.uBData = data
		break
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		u.Next = next
		return u
	})

	return nil
}

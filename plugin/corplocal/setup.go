package local

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("corplocal", setup) }

func setup(c *caddy.Controller) error {

	l := CorpLocal{}

	i := 0
	for c.Next() {
		if i > 0 {
			return plugin.ErrOnce
		}
		i++
		var corpdomainbase string
		if !c.Args(&corpdomainbase) {
			return c.ArgErr()
		}
		corpdomainbase = plugin.Host(corpdomainbase).Normalize()
		if corpdomainbase[0] != '.' {
			corpdomainbase = "." + corpdomainbase
		}
		l.corpDomain = ".ip" + corpdomainbase
		l.corpDomainV6 = ".ip6" + corpdomainbase
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		l.Next = next
		return l
	})

	return nil
}

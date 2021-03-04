package ubfile

import (
	"fmt"
	"net"
	"strconv"

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
	var randomv4ttl, randomv6ttl uint32
	for c.Next() {
		if i > 0 {
			return plugin.ErrOnce
		}
		i++
		f := NewUBDataFile()
		var filename string
		if !c.Args(&filename) {
			return c.ArgErr()
		}
		for c.NextBlock() {
			switch c.Val() {
			case "randomv4prefix":
				if !c.NextArg() {
					return c.ArgErr()
				}
				_, n, err := net.ParseCIDR(c.Val())
				if err != nil {
					return err
				}
				f.v4Allocator, err = NewV4PrefixAddAllocator(n, 5)
				if err != nil {
					return err
				}
			case "randomv6prefix":
				if !c.NextArg() {
					return c.ArgErr()
				}
				_, n, err := net.ParseCIDR(c.Val())
				if err != nil {
					return err
				}
				f.v6Allocator, err = NewV6AddAllocator(n, 5)
			case "randomv4ttl":
				if !c.NextArg() {
					return c.ArgErr()
				}
				v, err := strconv.ParseUint(c.Val(), 10, 32)
				if err != nil {
					return fmt.Errorf("%s is not a valid ttl", c.Val())
				}
				randomv4ttl = uint32(v)
			case "randomv6ttl":
				if !c.NextArg() {
					return c.ArgErr()
				}
				v, err := strconv.ParseUint(c.Val(), 10, 32)
				if err != nil {
					return fmt.Errorf("%s is not a valid ttl", c.Val())
				}
				randomv6ttl = uint32(v)
			default:
				return c.ArgErr()
			}
		}
		if f.v4Allocator != nil && randomv4ttl != 0 {
			f.v4Allocator.SetTTL(randomv4ttl)
		}

		if f.v6Allocator != nil && randomv6ttl != 0 {
			f.v6Allocator.SetTTL(randomv6ttl)
		}

		err := f.LoadFile(filename)
		if err != nil {
			return err
		}
		u.uBData = f
		break
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		u.Next = next
		return u
	})

	return nil
}

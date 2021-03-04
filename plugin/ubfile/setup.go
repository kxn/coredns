package ubfile

import (
	"fmt"
	"net"
	"regexp"
	"strconv"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("ubfile")

func init() { plugin.Register("ubfile", setup) }

func parseTTL(c *caddy.Controller) (uint32, error) {
	ttl := uint64(5)
	if c.NextArg() {
		t, err := strconv.ParseUint(c.Val(), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("Invalid ttl value %s", c.Val())
		}
		ttl = t
	}
	return uint32(ttl), nil
}

func setup(c *caddy.Controller) error {
	u := UBFile{}
	i := 0
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
			case "randomv4":
				if !c.NextArg() {
					return c.ArgErr()
				}
				addrs := c.Val()
				re := regexp.MustCompile(`([\d\.]+)-([\d\.]+)`)
				m := re.FindAllStringSubmatch(addrs, 1)
				if m != nil {
					start := net.ParseIP(m[0][1])
					end := net.ParseIP(m[0][2])
					if start == nil || end == nil {
						return fmt.Errorf("Unable to parse start ip %s or end ip %s", m[0][1], m[0][2])
					}
					ttl, err := parseTTL(c)
					if err != nil {
						return err
					}
					f.v4Allocator, err = NewV4StartEndAddAllocator(start, end, ttl)
					if err != nil {
						return err
					}

				} else {
					_, n, err := net.ParseCIDR(c.Val())
					if err != nil {
						return err
					}
					var ttl uint32
					ttl, err = parseTTL(c)
					if err != nil {
						return err
					}

					f.v4Allocator, err = NewV4PrefixAddAllocator(n, ttl)
					if err != nil {
						return err
					}

				}
				// can not have more args
				if c.NextArg() {
					return c.ArgErr()
				}

			case "randomv6":
				if !c.NextArg() {
					return c.ArgErr()
				}
				_, n, err := net.ParseCIDR(c.Val())
				if err != nil {
					return err
				}
				var ttl uint32
				ttl, err = parseTTL(c)
				if err != nil {
					return err
				}
				if c.NextArg() {
					switch c.Val() {
					case "add":
						f.v6Allocator, err = NewV6AddAllocator(n, ttl)
					case "hash":
						f.v6Allocator, err = NewV6HashAllocator(n, ttl)
					}
				} else {
					// defaults to add
					f.v6Allocator, err = NewV6AddAllocator(n, ttl)
				}
				if err != nil {
					return err
				}
				// can not have more args
				if c.NextArg() {
					return c.ArgErr()
				}
			default:
				return c.ArgErr()
			}
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

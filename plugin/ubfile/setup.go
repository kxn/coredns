package ubfile

import (
	"encoding/binary"
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
				// very ugly hack...
				switch len(n.IP) {
				case net.IPv4len:
					f.randomV4Prefix = binary.BigEndian.Uint32(n.IP)
				case net.IPv6len:
					f.randomV4Prefix = binary.BigEndian.Uint32(n.IP[12:])
				default:
					return fmt.Errorf("Internal error")
				}
			case "randomv6prefix":
				if !c.NextArg() {
					return c.ArgErr()
				}
				_, n, err := net.ParseCIDR(c.Val())
				if err != nil {
					return err
				}
				switch len(n.IP) {
				case net.IPv4len:
					return fmt.Errorf("%s is not a valid ipv6 prefix", c.Val())
				case net.IPv6len:
					f.randomV6Prefix = binary.BigEndian.Uint64(n.IP)
				default:
					return fmt.Errorf("Internal error")
				}
			case "randomv4ttl":
				if !c.NextArg() {
					return c.ArgErr()
				}
				v, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return fmt.Errorf("%s is not a valid ttl", c.Val())
				}
				f.randomV4Ttl = uint16(v)
			case "randomv6ttl":
				if !c.NextArg() {
					return c.ArgErr()
				}
				v, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return fmt.Errorf("%s is not a valid ttl", c.Val())
				}
				f.randomV6Ttl = uint16(v)
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

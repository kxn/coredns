package forward

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/pkg/parse"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/coredns/coredns/plugin/pkg/transport"
)

func init() { plugin.Register("forward", setup) }

func setup(c *caddy.Controller) error {
	for {
		f, err := parseForward(c)
		if err != nil {
			return plugin.Error("forward", err)
		}
		if f == nil {
			break
		}
		if f.Len() > max {
			return plugin.Error("forward", fmt.Errorf("more than %d TOs configured: %d", max, f.Len()))
		}

		dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
			f.Next = next
			return f
		})

		c.OnStartup(func() error {
			return f.OnStartup()
		})
		c.OnStartup(func() error {
			if taph := dnsserver.GetConfig(c).Handler("dnstap"); taph != nil {
				if tapPlugin, ok := taph.(dnstap.Dnstap); ok {
					f.tapPlugin = &tapPlugin
				}
			}
			return nil
		})

		c.OnShutdown(func() error {
			return f.OnShutdown()
		})
	}
	return nil
}

// OnStartup starts a goroutines for all proxies.
func (f *Forward) OnStartup() (err error) {
	for _, p := range f.proxies {
		p.start(f.hcInterval)
	}
	return nil
}

// OnShutdown stops all configured proxies.
func (f *Forward) OnShutdown() error {
	for _, p := range f.proxies {
		p.stop()
	}
	return nil
}

func parseForward(c *caddy.Controller) (*Forward, error) {
	var (
		f   *Forward
		err error
	)
	for c.Next() {
		f, err = parseStanza(c)
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	return nil, nil
}

func parseStanza(c *caddy.Controller) (*Forward, error) {
	f := New()

	if !c.Args(&f.from) {
		return f, c.ArgErr()
	}

	var (
		transports []string
	)
	if f.from != "FILE" {
		f.isFileForward = false
		f.from = plugin.Host(f.from).Normalize()
		to := c.RemainingArgs()
		if len(to) == 0 {
			return f, c.ArgErr()
		}

		toHosts, err := parse.HostPortOrFile(to...)
		if err != nil {
			return f, err
		}

		transports = make([]string, len(toHosts))
		allowedTrans := map[string]bool{"dns": true, "tls": true}
		for i, host := range toHosts {
			trans, h := parse.Transport(host)

			if !allowedTrans[trans] {
				return f, fmt.Errorf("'%s' is not supported as a destination protocol in forward: %s", trans, host)
			}
			p := NewProxy(h, trans)
			f.proxies = append(f.proxies, p)
			transports[i] = trans
		}
	} else {
		// Is a "FILE" syntax, read and parse the file into map
		f.isFileForward = true
		to := c.RemainingArgs()
		if len(to) != 1 {
			return f, c.ArgErr()
		}
		err := readForwardFromFile(to[0], f)
		if err != nil {
			return f, err
		}
		transports = make([]string, len(f.proxies))
		// We probably should fill it with "dns", but ..

	}

	for c.NextBlock() {
		if err := parseBlock(c, f); err != nil {
			return f, err
		}
	}

	if f.tlsServerName != "" {
		f.tlsConfig.ServerName = f.tlsServerName
	}

	// Initialize ClientSessionCache in tls.Config. This may speed up a TLS handshake
	// in upcoming connections to the same TLS server.
	f.tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(len(f.proxies))

	for i := range f.proxies {
		// Only set this for proxies that need it.
		if transports[i] == transport.TLS {
			f.proxies[i].SetTLSConfig(f.tlsConfig)
		}
		f.proxies[i].SetExpire(f.expire)
		f.proxies[i].health.SetRecursionDesired(f.opts.hcRecursionDesired)
	}

	return f, nil
}

func readForwardFromFile(filename string, f *Forward) error {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	var (
		currentProxyList *[]*Proxy
	)
	namedProxies := make(map[string]*Proxy)
	nameRe := regexp.MustCompile(`name:\s*([^\s]+)`)
	forwardAddrRe := regexp.MustCompile(`forward-addr:\s*([\d\.]+)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if strings.Contains(line, "name:") {
			m := nameRe.FindAllStringSubmatch(line, 1)
			if m != nil && len(m) == 1 && len(m[0]) == 2 {
				name := plugin.Host(m[0][1]).Normalize()
				_, ok := f.domainProxies[name]
				if !ok {
					f.domainProxies[name] = &[]*Proxy{}
				}
				currentProxyList = f.domainProxies[name]
				continue
			}
			return fmt.Errorf("Invalid line of name '%s'", line)
		}
		if strings.Contains(line, "forward-addr:") {
			m := forwardAddrRe.FindAllStringSubmatch(line, 1)
			if m != nil && len(m) == 1 && len(m[0]) == 2 {
				forwardAddr := m[0][1]
				p, ok := namedProxies[forwardAddr]
				if !ok {
					p = NewProxy(forwardAddr+":53", "dns")
					namedProxies[forwardAddr] = p
					f.proxies = append(f.proxies, p)
				}
				if currentProxyList == nil {
					return fmt.Errorf("Invalid file, forward-addr without name first")
				}
				*currentProxyList = append(*currentProxyList, p)
				continue
			}
			return fmt.Errorf("Invalid line of name '%s'", line)
		}

	}
	if scanner.Err() != nil {
		return scanner.Err()
	}
	// Everything should be setup right now
	return nil
}

func parseBlock(c *caddy.Controller, f *Forward) error {
	switch c.Val() {
	case "except":
		ignore := c.RemainingArgs()
		if len(ignore) == 0 {
			return c.ArgErr()
		}
		for i := 0; i < len(ignore); i++ {
			ignore[i] = plugin.Host(ignore[i]).Normalize()
		}
		f.ignored = ignore
	case "max_fails":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("max_fails can't be negative: %d", n)
		}
		f.maxfails = uint32(n)
	case "health_check":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("health_check can't be negative: %d", dur)
		}
		f.hcInterval = dur

		for c.NextArg() {
			switch hcOpts := c.Val(); hcOpts {
			case "no_rec":
				f.opts.hcRecursionDesired = false
			default:
				return fmt.Errorf("health_check: unknown option %s", hcOpts)
			}
		}

	case "force_tcp":
		if c.NextArg() {
			return c.ArgErr()
		}
		f.opts.forceTCP = true
	case "prefer_udp":
		if c.NextArg() {
			return c.ArgErr()
		}
		f.opts.preferUDP = true
	case "tls":
		args := c.RemainingArgs()
		if len(args) > 3 {
			return c.ArgErr()
		}

		tlsConfig, err := pkgtls.NewTLSConfigFromArgs(args...)
		if err != nil {
			return err
		}
		f.tlsConfig = tlsConfig
	case "tls_servername":
		if !c.NextArg() {
			return c.ArgErr()
		}
		f.tlsServerName = c.Val()
	case "expire":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("expire can't be negative: %s", dur)
		}
		f.expire = dur
	case "policy":
		if !c.NextArg() {
			return c.ArgErr()
		}
		switch x := c.Val(); x {
		case "random":
			f.p = &random{}
		case "round_robin":
			f.p = &roundRobin{}
		case "sequential":
			f.p = &sequential{}
		default:
			return c.Errf("unknown policy '%s'", x)
		}
	case "max_concurrent":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("max_concurrent can't be negative: %d", n)
		}
		f.ErrLimitExceeded = errors.New("concurrent queries exceeded maximum " + c.Val())
		f.maxConcurrent = int64(n)

	default:
		return c.Errf("unknown property '%s'", c.Val())
	}

	return nil
}

const max = 256 // Maximum number of upstreams.

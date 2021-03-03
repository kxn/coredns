package local

import (
	"context"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("corplocal")

// CorpLocal is a plugin that returns standard replies for local queries.
type CorpLocal struct {
	Next         plugin.Handler
	corpDomain   string // base name for corp domain, e.g  .ip.corp.google.com.
	corpDomainV6 string // base name for v6 corp domain, e.g  .ip6.corp.google.com.
}

func soaFromOrigin(origin string) []dns.RR {
	hdr := dns.RR_Header{Name: origin, Ttl: ttl, Class: dns.ClassINET, Rrtype: dns.TypeSOA}
	return []dns.RR{&dns.SOA{Hdr: hdr, Ns: "localhost.", Mbox: "root.localhost.", Serial: 1, Refresh: 0, Retry: 0, Expire: 0, Minttl: ttl}}
}

func isIPIntranet(ip net.IP) bool {
	switch len(ip) {
	case net.IPv4len:
		if ip[0] == 10 {
			// 10.0.0.0/8
			return true
		}
		if ip[0] == 172 && (ip[1]&0xf0) == 16 {
			// 172.16.0.0/12
			return true
		}
		if ip[0] == 192 && ip[1] == 168 {
			// 192.168.0.0/16
			return true
		}
		// link local address is NOT intranet address, but there might be some stupid programs do ptr lookup on this kind of address
		if ip[0] == 169 && ip[1] == 254 {
			// 169.254.0.0/16
			return true
		}
		// Carrier grade nat
		if ip[0] == 100 && (ip[1]&0xc0) == 64 {
			// 100.64.0.0/10
			return true
		}

		return false
	case net.IPv6len:
		// we don't process v4 in v6 addr, since this is from net.ParseIP
		if ip[0] == 0xfd && ip[1] == 0 {
			// fd00::/8
			return true
		}
		// link local
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			// fe80::/10
			return true
		}
		return false

	default:
		return false
	}
}

func returnNXDomain(source *dns.Msg, w dns.ResponseWriter) {
	m := new(dns.Msg)
	m.SetReply(source)
	m.Rcode = dns.RcodeNameError
	m.Authoritative = true
	m.MsgHdr.RecursionAvailable = true
	w.WriteMsg(m)
}

func returnOK(source *dns.Msg, w dns.ResponseWriter, answers []dns.RR) {
	m := new(dns.Msg)
	m.SetReply(source)
	m.Authoritative = true
	m.Answer = answers
	m.MsgHdr.RecursionAvailable = true
	w.WriteMsg(m)
}
func reverseByteArray(r []byte) []byte {
	lenx := len(r) //
	ret := make([]byte, lenx)
	for i := 0; i < lenx; i++ {
		ret[i] = r[lenx-(i+1)]
	}
	return ret
}

func makeA(name string, ip net.IP, ttl uint64) *dns.A {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.A = ip
	return r
}

func makeAAAA(name string, ip net.IP, ttl uint64) *dns.AAAA {
	r := new(dns.AAAA)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.AAAA = ip
	return r
}

func makePTR(name, ptr string, ttl uint64) *dns.PTR {
	r := new(dns.PTR)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Ptr = ptr
	return r
}

// ServeDNS implements the plugin.Handler interface.
func (l CorpLocal) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.QName()

	// return localhost for localhost. queries
	if state.Name() == "localhost." {
		reply := doLocalhost(state)
		w.WriteMsg(reply)
		return dns.RcodeSuccess, nil
	}

	// process ptr queries
	switch state.QType() {
	case dns.TypePTR:
		// localhost
		if qname == "1.0.0.127.in-addr.arpa." {
			returnOK(r, w, append([]dns.RR{}, makePTR(qname, "localhost.", ttl)))
			return dns.RcodeSuccess, nil
		}

		if strings.HasSuffix(qname, ".in-addr.arpa.") {
			ip := net.ParseIP(strings.TrimSuffix(qname, ".in-addr.arpa."))
			if ip == nil {
				returnNXDomain(r, w)
				return dns.RcodeNameError, nil
			}
			// HACK
			if len(ip) == net.IPv6len {
				// Truncate it !
				ip = ip[12:]
			}
			// reverse the ip
			ip = reverseByteArray(ip)
			// should only process intranet and local IPs, maybe carrier grade lan IP as well ?
			if isIPIntranet(ip) {
				returnOK(r, w, append([]dns.RR{}, makePTR(qname, ip.String()+l.corpDomain, ttl)))
				return dns.RcodeSuccess, nil

			}
			// should forward public rdns to the outer world
			break
		}

		if qname == "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa." {
			returnOK(r, w, append([]dns.RR{}, makePTR(qname, "localhost.", ttl)))
			return dns.RcodeSuccess, nil
		}

		if strings.HasSuffix(qname, ".ip6.arpa.") {
			ip6txt := strings.ReplaceAll(strings.TrimSuffix(qname, ".ip6.arpa."), ".", "")
			if len(ip6txt) != 32 {
				returnNXDomain(r, w)
				return dns.RcodeNameError, nil
			}
			ip6txt = string(reverseByteArray([]byte(ip6txt)))
			ip6t := []string{}
			for i := 0; i < 8; i++ {
				ip6t = append(ip6t, ip6txt[i*4:i*4+4])
			}
			ip6 := net.ParseIP(strings.Join(ip6t, ":"))
			if ip6 == nil {
				returnNXDomain(r, w)
				return dns.RcodeNameError, nil
			}
			if isIPIntranet(ip6) {
				returnOK(r, w, append([]dns.RR{}, makePTR(qname, strings.Join(ip6t, ".")+l.corpDomainV6, ttl)))
				return dns.RcodeSuccess, nil
			}
			break
		}

		// Invalid PTR type, return NXDOMAIN
		returnNXDomain(r, w)
		return dns.RcodeNameError, nil
	case dns.TypeA:
		if strings.HasSuffix(qname, l.corpDomain) {
			ip := net.ParseIP(strings.TrimSuffix(qname, l.corpDomain))
			// Do parse and return A
			if ip != nil {
				returnOK(r, w, append([]dns.RR{}, makeA(qname, ip, ttl)))
				return dns.RcodeSuccess, nil
			}
			// return NXDOMAIN for invalid format
			returnNXDomain(r, w)
			return dns.RcodeNameError, nil
		}
	case dns.TypeAAAA:
		if strings.HasSuffix(qname, l.corpDomainV6) {
			ip6 := net.ParseIP(strings.ReplaceAll(strings.TrimSuffix(qname, l.corpDomainV6), ".", ":"))
			if ip6 != nil {
				returnOK(r, w, append([]dns.RR{}, makeAAAA(qname, ip6, ttl)))
				return dns.RcodeSuccess, nil
			}
			returnNXDomain(r, w)
			return dns.RcodeNameError, nil
		}
	}
	return plugin.NextOrFailure(l.Name(), l.Next, ctx, w, r)
}

// Name implements the plugin.Handler interface.
func (l CorpLocal) Name() string { return "corplocal" }

func doLocalhost(state request.Request) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(state.Req)
	switch state.QType() {
	case dns.TypeA:
		hdr := dns.RR_Header{Name: state.QName(), Ttl: ttl, Class: dns.ClassINET, Rrtype: dns.TypeA}
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP("127.0.0.1").To4()}}
	case dns.TypeAAAA:
		hdr := dns.RR_Header{Name: state.QName(), Ttl: ttl, Class: dns.ClassINET, Rrtype: dns.TypeAAAA}
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("::1")}}
	default:
		// nodata
		m.Ns = soaFromOrigin(state.QName())
	}
	return m
}

const ttl = 604800

package ubfile

import (
	"context"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// UBFile is a unbound localdata file plugin
type UBFile struct {
	Next   plugin.Handler
	uBData UBDataFile
}

func (u UBFile) returnOK(source *dns.Msg, w dns.ResponseWriter, answers []dns.RR) {
	m := new(dns.Msg)
	m.SetReply(source)
	m.Authoritative = true
	m.Answer = answers
	m.MsgHdr.RecursionAvailable = true
	w.WriteMsg(m)
}

func (u UBFile) returnNXDomain(source *dns.Msg, w dns.ResponseWriter, zonename string) {
	// try to find SOA in this zone, if no SOA exists, craft one using default parameter
	zrecs, ok := u.uBData.Records[zonename]
	var zlist []dns.RR = nil
	if ok {
		zl, ok := zrecs.rr[dns.TypeSOA]
		if ok {
			zlist = zl
		}
	}
	if zlist == nil {
		// craft one using default parameter
		soa := new(dns.SOA)
		soa.Hdr = dns.RR_Header{Name: zonename, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 86400}
		soa.Ns = zonename
		soa.Mbox = "admin." + zonename
		soa.Serial = 2021022301
		soa.Refresh = 600
		soa.Retry = 3600
		soa.Expire = 604800
		soa.Minttl = 86400
		zlist = make([]dns.RR, 1)
		zlist[0] = soa
	}
	m := new(dns.Msg)
	m.SetReply(source)
	m.Rcode = dns.RcodeNameError
	m.Authoritative = true
	m.MsgHdr.RecursionAvailable = true
	m.Ns = zlist
	w.WriteMsg(m)
}

// ServeDNS implements the plugin.Handle interface.
func (u UBFile) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := strings.ToLower(state.Req.Question[0].Name)

	//answers := []dns.RR{}
	recs, ok := u.uBData.Records[qname]
	if ok {
		switch state.QType() {
		case dns.TypeA, dns.TypeMX, dns.TypeSRV, dns.TypePTR, dns.TypeSOA:
			rlist, ok := recs.rr[state.QType()]
			if ok {
				u.returnOK(r, w, rlist)
				return dns.RcodeSuccess, nil
			}
		}
	}
	var (
		off int
		end bool
	)
	for {
		if zone, ok := u.uBData.Zones[qname[off:]]; ok {
			switch zone.zonetype {
			case zoneStatic:
				// return NXDOMAIN
				u.returnNXDomain(r, w, zone.fqdn)
				return dns.RcodeSuccess, nil
			case zoneTransparent:
				// break and next
				break
			case zoneRedirect:
				// only lookup for A type questions, otherwise make it NXDOMAIN
				if state.QType() != dns.TypeA {
					u.returnNXDomain(r, w, zone.fqdn)
					return dns.RcodeSuccess, nil
				}
				if zone.ips == nil {
					u.returnNXDomain(r, w, zone.fqdn)
					return dns.RcodeSuccess, nil
				}
				// we can not simply return the list -- we need patch the names
				newlist := make([]dns.RR, len(*zone.ips))
				for i := 0; i < len(newlist); i++ {
					r := (*zone.ips)[i]
					r.Hdr = dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: r.Header().Ttl}
					newlist[i] = &r
				}
				u.returnOK(r, w, newlist)
				return dns.RcodeSuccess, nil
			}
		}
		off, end = dns.NextLabel(qname, off)
		if end {
			break
		}
	}

	// Still not find any zone, defaults to next
	return plugin.NextOrFailure(u.Name(), u.Next, ctx, w, r)

}

// Name implements the plugin.Handle interface.
func (u UBFile) Name() string { return "ubfile" }

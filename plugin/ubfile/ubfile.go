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
		zlist = zrecs.rr[dns.TypeSOA]
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

	recs, ok := u.uBData.Records[qname]
	if ok {
		u.returnOK(r, w, recs.rr[state.QType()])
		return dns.RcodeSuccess, nil
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
				// back lookup zone name in hosts
				recs, ok := u.uBData.Records[zone.fqdn]
				if !ok {
					// looks like we have a zone configured as redirect but without any records
					u.returnOK(r, w, nil)
					return dns.RcodeSuccess, nil
				}
				rlist, ok := recs.rr[state.QType()]
				if !ok {
					// We have the domain configured, but without the type requested
					u.returnOK(r, w, nil)
					return dns.RcodeSuccess, nil
				}
				// make a copy of the rr records
				// TODO we have a bug here , if redirected domain has rrs that we do not support configured, it would cause a SERVFAIL
				newlist := make([]dns.RR, len(rlist))
				for i := 0; i < len(newlist); i++ {
					var r dns.RR
					switch state.QType() {
					case dns.TypeA:
						r = copyA(qname, rlist[i])
					case dns.TypeMX:
						r = copyMX(qname, rlist[i])
					case dns.TypePTR:
						r = copyPTR(qname, rlist[i])
					}
					if r == nil {
						return dns.RcodeServerFailure, nil
					}
					newlist[i] = r
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

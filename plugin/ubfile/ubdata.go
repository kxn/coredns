package ubfile

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type dnsRecord struct {
	fqdn string
	rr   map[uint16][]dns.RR
	zone *dnsZone
}

type zoneType int8

const (
	zoneStatic = iota
	zoneTransparent
	zoneRedirect
)

type dnsZone struct {
	fqdn              string
	zonetype          zoneType
	redirectedRecord  *dnsRecord
	needRandomlizeARR bool
	parent            *UBDataFile
}

// UBDataFile  hold everything the unbound file knows
type UBDataFile struct {
	Records                                        map[string]*dnsRecord
	Zones                                          map[string]*dnsZone
	zoneRe, dataRe, soaRe, mxRe, aRe, ptrRe, srvRe *regexp.Regexp
	allocatedIPIndex                               int32
	allocatedIPs                                   sync.Map
}

func newUBDataFile() *UBDataFile {
	ret := UBDataFile{
		Records: map[string]*dnsRecord{},
		Zones:   map[string]*dnsZone{},
	}
	ret.zoneRe = regexp.MustCompile(`local-zone:\s*\"*([^\s^\"]+)\"*\s+([\w]+)`)
	ret.dataRe = regexp.MustCompile(`local-data:\s*\"([^\"]+)\"`)

	ret.aRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+a\s+([\d\.]+)`)
	ret.mxRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+mx\s+([\d\.]+)\s+([^\s]+)`)
	ret.soaRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+soa\s+([^\s]+)\s+([^\s]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)`)
	ret.srvRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+srv\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([^\s]+)`)
	ret.ptrRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+ptr\s+([^\s]+)`)

	ret.allocatedIPIndex = 0
	ret.allocatedIPs = sync.Map{}

	return &ret
}

func (u *UBDataFile) parseAndAddRecord(line string) error {
	m := u.aRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		name := plugin.Host(m[0][1]).Normalize()
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		r := makeA(name, m[0][3], ttl)
		u.getRecord(name).addRR(r)
		return nil
	}

	m = u.mxRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		name := plugin.Host(m[0][1]).Normalize()
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		pref, _ := strconv.ParseUint(m[0][3], 10, 16)
		mx := plugin.Host(m[0][4]).Normalize()
		r := makeMX(name, mx, ttl, pref)
		u.getRecord(name).addRR(r)
		return nil
	}

	m = u.srvRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		name := plugin.Host(m[0][1]).Normalize()
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		pref, _ := strconv.ParseUint(m[0][3], 10, 16)
		weight, _ := strconv.ParseUint(m[0][4], 10, 16)
		port, _ := strconv.ParseUint(m[0][5], 10, 16)
		target := plugin.Host(m[0][6]).Normalize()
		r := makeSRV(name, target, ttl, pref, weight, port)
		u.getRecord(name).addRR(r)
		return nil
	}

	m = u.ptrRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		name := plugin.Host(m[0][1]).Normalize()
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		ptr := plugin.Host(m[0][3]).Normalize()
		r := makePTR(name, ptr, ttl)
		u.getRecord(name).addRR(r)
		return nil
	}

	m = u.soaRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		name := plugin.Host(m[0][1]).Normalize()
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		serial, _ := strconv.ParseUint(m[0][5], 10, 32)
		refresh, _ := strconv.ParseUint(m[0][6], 10, 32)
		retry, _ := strconv.ParseUint(m[0][7], 10, 32)
		expire, _ := strconv.ParseUint(m[0][8], 10, 32)
		minttl, _ := strconv.ParseUint(m[0][9], 10, 32)
		ns := plugin.Host(m[0][3]).Normalize()
		mbox := plugin.Host(m[0][4]).Normalize()
		r := makeSOA(name, ns, mbox, ttl, serial, refresh, retry, expire, minttl)
		u.getRecord(name).addRR(r)
		return nil
	}
	return fmt.Errorf("Invalid local data %s", line)
}

// LoadUBFile create from file
func LoadUBFile(filepath string) (*UBDataFile, error) {
	u := newUBDataFile()
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if strings.Contains(line, "local-zone:") {
			m := u.zoneRe.FindAllStringSubmatch(line, 1)
			if m != nil && len(m) == 1 && len(m[0]) == 3 {
				zone := newZone(plugin.Host(m[0][1]).Normalize(), u)
				_, ok := u.Zones[zone.fqdn]
				if ok {
					return u, fmt.Errorf("Duplicate zone %s of line '%s'", zone.fqdn, line)
				}
				switch m[0][2] {
				case "static":
					zone.zonetype = zoneStatic
				case "typetransparent":
					zone.zonetype = zoneTransparent
				case "redirect":
					zone.zonetype = zoneRedirect
				default:
					return u, fmt.Errorf("Invalid zone type %s of line '%s'", m[0][2], line)
				}
				u.Zones[zone.fqdn] = &zone
				continue
			}
			return u, fmt.Errorf("Invalid line of local-zone '%s'", line)
		}
		if strings.Contains(line, "local-data:") {
			m := u.dataRe.FindAllStringSubmatch(line, 1)
			if m != nil && len(m) == 1 && len(m[0]) == 2 {
				err := u.parseAndAddRecord(m[0][1])
				if err != nil {
					return u, err
				}
				continue
			}
			return u, fmt.Errorf("Invalid line of local-data '%s'", line)
		}
		if strings.Trim(line, " \t\r\n") != "" {
			return u, fmt.Errorf("Unrecognized line '%s'", line)
		}
	}
	if scanner.Err() != nil {
		return u, scanner.Err()
	}
	// Scan for all redirected zones, and populate redirected pointers
	redirectedzones := []string{}
	for k, v := range u.Zones {
		if v.zonetype == zoneRedirect {
			redirectedzones = append(redirectedzones, k)
		}
	}
	// use all zero ip as randomlized ip
	for _, k := range redirectedzones {
		rr, ok := u.Records[k]
		if ok {
			u.Zones[k].redirectedRecord = rr
			if hasRandomizedARecord(rr) {
				u.Zones[k].needRandomlizeARR = true
			}
		}
	}
	// pre-allocate all randomlized ip
	allrecordkeys := []string{}
	for k := range u.Records {
		allrecordkeys = append(allrecordkeys, k)
	}
	for _, k := range allrecordkeys {
		if hasRandomizedARecord(u.Records[k]) {
			u.Records[k].rr[dns.TypeA] = u.allocateIP(k)
		}
	}
	// Refill the zone information for all records
	for _, k := range allrecordkeys {
		var (
			off int
			end bool
		)
		for {
			if zone, ok := u.Zones[k[off:]]; ok {
				u.Records[k].zone = zone
				break
			}
			off, end = dns.NextLabel(k, off)
			if end {
				break
			}
		}
	}

	return u, nil
}

func hasRandomizedARecord(r *dnsRecord) bool {
	zeroip := net.IPv4(0, 0, 0, 0)
	arecords, ok := r.rr[dns.TypeA]
	if ok {
		for _, aitem := range arecords {
			a, ok := aitem.(*dns.A)
			if ok && a.A.Equal(zeroip) {
				return true
			}
		}
	}
	return false
}

func (u *UBDataFile) getRecord(fqdn string) *dnsRecord {
	rec, ok := u.Records[fqdn]
	if ok {
		return rec
	}
	u.Records[fqdn] = &dnsRecord{fqdn: fqdn, rr: map[uint16][]dns.RR{}, zone: nil}
	rec = u.Records[fqdn]
	return rec
}

func (u *UBDataFile) allocateIP(name string) []dns.RR {
	r, ok := u.allocatedIPs.Load(name)
	if ok {
		return r.([]dns.RR)
	}
	rr := []dns.RR{}
	arecord := new(dns.A)
	arecord.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600}
	c := atomic.AddInt32(&u.allocatedIPIndex, 1)
	c1 := c / 256
	c2 := c % 256
	arecord.A = net.IPv4(172, 16, byte(c1), byte(c2))
	rr = append(rr, arecord)
	u.allocatedIPs.Store(name, rr)
	return rr
}

func newZone(fqdn string, u *UBDataFile) dnsZone {
	r := dnsZone{fqdn: fqdn}
	r.needRandomlizeARR = false
	r.redirectedRecord = nil
	r.zonetype = zoneStatic
	r.parent = u
	return r
}

// GetRedirectedRecord
func (z *dnsZone) GetRedirectedRecord(qname string, qtype uint16) []dns.RR {
	if z.redirectedRecord == nil {
		return nil
	}
	rrs := z.redirectedRecord.rr[qtype]
	if rrs == nil {
		return nil
	}
	if qtype == dns.TypeA && z.needRandomlizeARR {
		return z.parent.allocateIP(qname)
	}
	newlist := make([]dns.RR, len(rrs))
	for i := 0; i < len(newlist); i++ {
		var r dns.RR
		switch qtype {
		case dns.TypeA:
			r = copyA(qname, rrs[i])
		case dns.TypeMX:
			r = copyMX(qname, rrs[i])
		case dns.TypePTR:
			r = copyPTR(qname, rrs[i])
		}
		newlist[i] = r
	}
	return newlist
}

func (d *dnsRecord) addRR(r dns.RR) {
	t := r.Header().Rrtype
	_, ok := d.rr[t]
	if !ok {
		d.rr[t] = []dns.RR{}
	}
	d.rr[t] = append(d.rr[t], r)
}

func makeA(name, ip string, ttl uint64) *dns.A {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.A = net.ParseIP(ip)
	return r
}

func copyA(newname string, r dns.RR) *dns.A {
	source, ok := r.(*dns.A)
	if !ok {
		return nil
	}
	ret := new(dns.A)
	ret.Hdr = dns.RR_Header{Name: newname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: source.Header().Ttl}
	ret.A = source.A
	return ret
}

func makeMX(name, mx string, ttl, pref uint64) *dns.MX {
	r := new(dns.MX)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Mx = mx
	r.Preference = uint16(pref)
	return r
}

func copyMX(newname string, r dns.RR) *dns.MX {
	source, ok := r.(*dns.MX)
	if !ok {
		return nil
	}
	ret := new(dns.MX)
	ret.Hdr = dns.RR_Header{Name: newname, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: source.Header().Ttl}
	ret.Mx = source.Mx
	ret.Preference = source.Preference
	return ret
}

func makePTR(name, ptr string, ttl uint64) *dns.PTR {
	r := new(dns.PTR)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Ptr = ptr
	return r
}

func copyPTR(newname string, r dns.RR) *dns.PTR {
	source, ok := r.(*dns.PTR)
	if !ok {
		return nil
	}
	ret := new(dns.PTR)
	ret.Hdr = dns.RR_Header{Name: newname, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: source.Header().Ttl}
	ret.Ptr = source.Ptr
	return ret
}

func makeSRV(name, target string, ttl, prio, weight, port uint64) *dns.SRV {
	r := new(dns.SRV)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Target = target
	r.Priority = uint16(prio)
	r.Port = uint16(port)
	r.Weight = uint16(weight)
	return r
}

func makeSOA(name, ns, mbox string, ttl, serial, refresh, retry, expire, minttl uint64) *dns.SOA {
	r := new(dns.SOA)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Ns = ns
	r.Mbox = mbox
	r.Serial = uint32(serial)
	r.Refresh = uint32(refresh)
	r.Retry = uint32(retry)
	r.Expire = uint32(expire)
	r.Minttl = uint32(minttl)
	return r
}

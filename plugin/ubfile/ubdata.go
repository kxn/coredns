package ubfile

import (
	"bufio"
	"encoding/binary"
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
	fqdn                 string
	zonetype             zoneType
	redirectedRecord     *dnsRecord
	needRandomlizeARR    bool
	needRandomlizeAAAARR bool
	parent               *UBDataFile
}

// UBDataFile  hold everything the unbound file knows
type UBDataFile struct {
	Records                                                map[string]*dnsRecord
	Zones                                                  map[string]*dnsZone
	zoneRe, dataRe, soaRe, mxRe, aRe, aaaaRe, ptrRe, srvRe *regexp.Regexp
	allocatedV4IPIndex, allocatedV6IPIndex                 uint32
	allocatedV4IPs, allocatedV6IPs                         sync.Map
	randomV4Prefix                                         uint32
	randomV6Prefix                                         uint64
	randomV4Ttl, randomV6Ttl                               uint16
	randomV4IP, randomV6IP                                 net.IP
}

// NewUBDataFile create a new object
func NewUBDataFile() *UBDataFile {
	ret := UBDataFile{
		Records: map[string]*dnsRecord{},
		Zones:   map[string]*dnsZone{},
	}
	ret.zoneRe = regexp.MustCompile(`local-zone:\s*\"*([^\s^\"]+)\"*\s+([\w]+)`)
	ret.dataRe = regexp.MustCompile(`local-data:\s*\"([^\"]+)\"`)

	ret.aRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+a\s+([\d\.]+)`)
	ret.aaaaRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+aaaa\s+([abcdef\d\:]+)`)
	ret.mxRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+mx\s+([\d\.]+)\s+([^\s]+)`)
	ret.soaRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+soa\s+([^\s]+)\s+([^\s]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)`)
	ret.srvRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+srv\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([^\s]+)`)
	ret.ptrRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+ptr\s+([^\s]+)`)

	ret.allocatedV4IPIndex = 0
	ret.allocatedV6IPIndex = 0
	ret.allocatedV4IPs = sync.Map{}
	ret.allocatedV6IPs = sync.Map{}
	ret.randomV4Prefix = 0
	ret.randomV6Prefix = 0
	ret.randomV4Ttl = 5
	ret.randomV6Ttl = 5
	ret.randomV4IP = make(net.IP, net.IPv4len)
	ret.randomV6IP = make(net.IP, net.IPv6len)
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

	m = u.aaaaRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		name := plugin.Host(m[0][1]).Normalize()
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		r := makeAAAA(name, m[0][3], ttl)
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

// LoadFile create from file
func (u *UBDataFile) LoadFile(filepath string) error {
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
					return fmt.Errorf("Duplicate zone %s of line '%s'", zone.fqdn, line)
				}
				switch m[0][2] {
				case "static":
					zone.zonetype = zoneStatic
				case "typetransparent":
					zone.zonetype = zoneTransparent
				case "redirect":
					zone.zonetype = zoneRedirect
				default:
					return fmt.Errorf("Invalid zone type %s of line '%s'", m[0][2], line)
				}
				u.Zones[zone.fqdn] = &zone
				continue
			}
			return fmt.Errorf("Invalid line of local-zone '%s'", line)
		}
		if strings.Contains(line, "local-data:") {
			m := u.dataRe.FindAllStringSubmatch(line, 1)
			if m != nil && len(m) == 1 && len(m[0]) == 2 {
				err := u.parseAndAddRecord(m[0][1])
				if err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("Invalid line of local-data '%s'", line)
		}
		if strings.Trim(line, " \t\r\n") != "" {
			return fmt.Errorf("Unrecognized line '%s'", line)
		}
	}
	if scanner.Err() != nil {
		return scanner.Err()
	}
	// Scan for all redirected zones, and populate redirected pointers
	redirectedzones := []string{}
	for k, v := range u.Zones {
		if v.zonetype == zoneRedirect {
			redirectedzones = append(redirectedzones, k)
		}
	}
	for _, k := range redirectedzones {
		rr, ok := u.Records[k]
		if ok {
			u.Zones[k].redirectedRecord = rr
			if u.hasRandomizedARecord(rr) {
				u.Zones[k].needRandomlizeARR = true
			}
			if u.hasRandomizedAAAARecord(rr) {
				u.Zones[k].needRandomlizeAAAARR = true
			}
		}
	}
	// pre-allocate all randomlized ip
	allrecordkeys := []string{}
	for k := range u.Records {
		allrecordkeys = append(allrecordkeys, k)
	}
	for _, k := range allrecordkeys {
		if u.hasRandomizedARecord(u.Records[k]) {
			if u.randomV4Prefix == 0 {
				return fmt.Errorf("data contains randomlized IP %s, but randomv4prefix has not been specified", u.randomV4IP.String())
			}
			u.Records[k].rr[dns.TypeA] = u.allocateV4IP(k)
		}
		if u.hasRandomizedAAAARecord(u.Records[k]) {
			if u.randomV6Prefix == 0 {
				return fmt.Errorf("data contains randomlized IPv6 %s, but randomv6prefix has not been specified", u.randomV6IP.String())
			}
			u.Records[k].rr[dns.TypeAAAA] = u.allocateV6IP(k)
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

	return nil
}

func (u *UBDataFile) hasRandomizedARecord(r *dnsRecord) bool {
	arecords, ok := r.rr[dns.TypeA]
	if ok {
		for _, aitem := range arecords {
			a, ok := aitem.(*dns.A)
			if ok && a.A.Equal(u.randomV4IP) {
				return true
			}
		}
	}
	return false
}

func (u *UBDataFile) hasRandomizedAAAARecord(r *dnsRecord) bool {
	arecords, ok := r.rr[dns.TypeAAAA]
	if ok {
		for _, aitem := range arecords {
			a, ok := aitem.(*dns.AAAA)
			if ok && a.AAAA.Equal(u.randomV6IP) {
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

func (u *UBDataFile) allocateV4IP(name string) []dns.RR {
	r, ok := u.allocatedV4IPs.Load(name)
	if ok {
		return r.([]dns.RR)
	}
	rr := []dns.RR{}
	arecord := new(dns.A)
	arecord.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(u.randomV4Ttl)}
	c := u.randomV4Prefix + atomic.AddUint32(&u.allocatedV4IPIndex, 1)
	arecord.A = make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(arecord.A, uint32(c))
	rr = append(rr, arecord)
	u.allocatedV4IPs.Store(name, rr)
	return rr
}

func (u *UBDataFile) allocateV6IP(name string) []dns.RR {
	r, ok := u.allocatedV6IPs.Load(name)
	if ok {
		return r.([]dns.RR)
	}
	rr := []dns.RR{}
	arecord := new(dns.AAAA)
	arecord.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(u.randomV6Ttl)}
	arecord.AAAA = make(net.IP, net.IPv6len)
	binary.BigEndian.PutUint64(arecord.AAAA, u.randomV6Prefix)
	binary.BigEndian.PutUint64(arecord.AAAA[8:], uint64(atomic.AddUint32(&u.allocatedV6IPIndex, 1)))
	rr = append(rr, arecord)
	u.allocatedV6IPs.Store(name, rr)
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
		return z.parent.allocateV4IP(qname)
	}
	if qtype == dns.TypeAAAA && z.needRandomlizeAAAARR {
		return z.parent.allocateV6IP(qname)
	}

	newlist := make([]dns.RR, len(rrs))
	for i := 0; i < len(newlist); i++ {
		var r dns.RR
		switch qtype {
		case dns.TypeA:
			r = copyA(qname, rrs[i])
		case dns.TypeAAAA:
			r = copyAAAA(qname, rrs[i])
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

func makeAAAA(name, ip string, ttl uint64) *dns.AAAA {
	r := new(dns.AAAA)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.AAAA = net.ParseIP(ip)
	return r
}

func copyAAAA(newname string, r dns.RR) *dns.AAAA {
	source, ok := r.(*dns.AAAA)
	if !ok {
		return nil
	}
	ret := new(dns.AAAA)
	ret.Hdr = dns.RR_Header{Name: newname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: source.Header().Ttl}
	ret.AAAA = source.AAAA
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

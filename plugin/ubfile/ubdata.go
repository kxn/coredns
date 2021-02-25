package ubfile

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type dnsRecord struct {
	fqdn string
	rr   map[uint16][]dns.RR
}

type zoneType int8

const (
	zoneStatic = iota
	zoneTransparent
	zoneRedirect
)

type dnsZone struct {
	fqdn     string
	zonetype zoneType
	ips      *[]dns.A // mainly a hack to store original data for redirect zone lookup
}

// UBDataFile  hold everything the unbound file knows
type UBDataFile struct {
	Records                                        map[string]*dnsRecord
	Zones                                          map[string]*dnsZone
	zoneRe, dataRe, soaRe, mxRe, aRe, ptrRe, srvRe *regexp.Regexp
	// very ugly name to remind myself to remove it ...
	temp map[string]*[]dns.A
}

func newUBDataFile() UBDataFile {
	ret := UBDataFile{
		Records: map[string]*dnsRecord{},
		Zones:   map[string]*dnsZone{},
		temp:    map[string]*[]dns.A{},
	}
	ret.zoneRe = regexp.MustCompile(`local-zone:\s*\"*([^\s^\"]+)\"*\s+([\w]+)`)
	ret.dataRe = regexp.MustCompile(`local-data:\s*\"([^\"]+)\"`)

	ret.aRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+a\s+([\d\.]+)`)
	ret.mxRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+mx\s+([\d\.]+)\s+([^\s]+)`)
	ret.soaRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+soa\s+([^\s]+)\s+([^\s]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)`)
	ret.srvRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+srv\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([^\s]+)`)
	ret.ptrRe = regexp.MustCompile(`([^\s]+)\s+([\d]+)\s+in\s+ptr\s+([^\s]+)`)
	return ret
}

func (u *UBDataFile) parseAndAddRecord(line string) error {
	m := u.aRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		name := plugin.Host(m[0][1]).Normalize()
		u.getRecord(name).addA(m[0][3], ttl)
		// Hack to keep a record
		_, ok := u.temp[name]
		if !ok {
			u.temp[name] = &[]dns.A{}
		}
		r := dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)},
			A:   net.ParseIP(m[0][3]),
		}
		*u.temp[name] = append(*u.temp[name], r)
		return nil
	}

	m = u.mxRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		pref, _ := strconv.ParseUint(m[0][3], 10, 16)
		mx := plugin.Host(m[0][4]).Normalize()
		u.getRecord(plugin.Host(m[0][1]).Normalize()).addMX(mx, ttl, pref)
		return nil
	}

	m = u.srvRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		pref, _ := strconv.ParseUint(m[0][3], 10, 16)
		weight, _ := strconv.ParseUint(m[0][4], 10, 16)
		port, _ := strconv.ParseUint(m[0][5], 10, 16)
		target := plugin.Host(m[0][6]).Normalize()
		u.getRecord(plugin.Host(m[0][1]).Normalize()).addSRV(target, ttl, pref, weight, port)
		return nil
	}

	m = u.ptrRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		ptr := plugin.Host(m[0][3]).Normalize()
		u.getRecord(plugin.Host(m[0][1]).Normalize()).addPTR(ptr, ttl)
		return nil
	}

	m = u.soaRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		serial, _ := strconv.ParseUint(m[0][5], 10, 32)
		refresh, _ := strconv.ParseUint(m[0][6], 10, 32)
		retry, _ := strconv.ParseUint(m[0][7], 10, 32)
		expire, _ := strconv.ParseUint(m[0][8], 10, 32)
		minttl, _ := strconv.ParseUint(m[0][9], 10, 32)
		ns := plugin.Host(m[0][3]).Normalize()
		mbox := plugin.Host(m[0][4]).Normalize()
		u.getRecord(plugin.Host(m[0][1]).Normalize()).addSOA(ns, mbox, ttl, serial, refresh, retry, expire, minttl)
		return nil
	}
	return fmt.Errorf("Invalid local data %s", line)
}

// LoadUBFile create from file
func LoadUBFile(filepath string) (UBDataFile, error) {
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
				zone := dnsZone{fqdn: plugin.Host(m[0][1]).Normalize()}
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
	// Everything should be setup right now
	// hack, fill all redirect zones with dns.A arrays
	redirectedkeys := []string{}
	for k, v := range u.Zones {
		if v.zonetype == zoneRedirect {
			redirectedkeys = append(redirectedkeys, k)
		}
	}
	for _, k := range redirectedkeys {
		r, ok := u.temp[k]
		if ok {
			u.Zones[k].ips = r
		}
	}
	u.temp = nil
	return u, nil
}

func (u *UBDataFile) getRecord(fqdn string) *dnsRecord {
	rec, ok := u.Records[fqdn]
	if ok {
		return rec
	}
	u.Records[fqdn] = &dnsRecord{fqdn: fqdn, rr: map[uint16][]dns.RR{}}
	rec = u.Records[fqdn]
	return rec
}

func (d *dnsRecord) addRR(t uint16, r dns.RR) {
	_, ok := d.rr[t]
	if !ok {
		d.rr[t] = []dns.RR{}
	}
	d.rr[t] = append(d.rr[t], r)
}

func (d *dnsRecord) addA(ip string, ttl uint64) {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: d.fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.A = net.ParseIP(ip)
	d.addRR(dns.TypeA, r)
}

func (d *dnsRecord) addMX(mx string, ttl, pref uint64) {
	r := new(dns.MX)
	r.Hdr = dns.RR_Header{Name: d.fqdn, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Mx = mx
	r.Preference = uint16(pref)
	d.addRR(dns.TypeMX, r)
}

func (d *dnsRecord) addPTR(ptr string, ttl uint64) {
	r := new(dns.PTR)
	r.Hdr = dns.RR_Header{Name: d.fqdn, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Ptr = ptr
	d.addRR(dns.TypePTR, r)
}

func (d *dnsRecord) addSRV(target string, ttl, prio, weight, port uint64) {
	r := new(dns.SRV)
	r.Hdr = dns.RR_Header{Name: d.fqdn, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Target = target
	r.Priority = uint16(prio)
	r.Port = uint16(port)
	r.Weight = uint16(weight)
	d.addRR(dns.TypeSRV, r)
}

func (d *dnsRecord) addSOA(ns, mbox string, ttl, serial, refresh, retry, expire, minttl uint64) {
	r := new(dns.SOA)
	r.Hdr = dns.RR_Header{Name: d.fqdn, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Ns = ns
	r.Mbox = mbox
	r.Serial = uint32(serial)
	r.Refresh = uint32(refresh)
	r.Retry = uint32(retry)
	r.Expire = uint32(expire)
	r.Minttl = uint32(minttl)
	d.addRR(dns.TypeSOA, r)
}

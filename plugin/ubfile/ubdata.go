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
}

func newUBDataFile() UBDataFile {
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
	return ret
}

func (u *UBDataFile) parseAndAddRecord(line string, temp map[string][]dns.A) error {
	m := u.aRe.FindAllStringSubmatch(line, 1)
	if m != nil {
		name := plugin.Host(m[0][1]).Normalize()
		ttl, _ := strconv.ParseUint(m[0][2], 10, 32)
		r := makeA(name, m[0][3], ttl)
		u.getRecord(name).addRR(r)
		// Hack to keep a record
		_, ok := temp[name]
		if !ok {
			temp[name] = []dns.A{}
		}
		temp[name] = append(temp[name], *r)
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
func LoadUBFile(filepath string) (UBDataFile, error) {
	u := newUBDataFile()
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	temp := map[string][]dns.A{}

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
				err := u.parseAndAddRecord(m[0][1], temp)
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
		r, ok := temp[k]
		if ok {
			u.Zones[k].ips = &r
		}
	}
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

func makeMX(name, mx string, ttl, pref uint64) *dns.MX {
	r := new(dns.MX)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Mx = mx
	r.Preference = uint16(pref)
	return r
}

func makePTR(name, ptr string, ttl uint64) *dns.PTR {
	r := new(dns.PTR)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: uint32(ttl)}
	r.Ptr = ptr
	return r
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

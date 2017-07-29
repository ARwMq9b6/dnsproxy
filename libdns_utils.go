package dnsproxy

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ARwMq9b6/dnsproxy/dns_over_https/google"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
)

// --- impl dns.Msg
func MsgNewReplyFromReq(req *dns.Msg, answer ...dns.RR) *dns.Msg {
	resp := new(dns.Msg)

	resp.Id = req.Id
	resp.Response = true
	resp.Opcode = req.Opcode
	resp.Rcode = dns.RcodeSuccess
	if len(req.Question) > 0 {
		resp.Question = make([]dns.Question, 1)
		resp.Question[0] = req.Question[0]
	}

	resp.RecursionAvailable = true
	resp.Answer = answer
	return resp
}

// Perform query into Google DNS over HTTPS server
func MsgExchangeOverGoogleDOH(req *dns.Msg, rt http.RoundTripper) (resp *dns.Msg, err error) {
	qtype := req.Question[0].Qtype
	name := req.Question[0].Name

	var ecs net.IP
	opt := req.IsEdns0()
	if opt != nil {
		for _, s := range opt.Option {
			if _ecs, ok := s.(*dns.EDNS0_SUBNET); ok {
				ecs = _ecs.Address
			}
		}
	}
	dohresp, err := google.Query(rt, qtype, name, ecs.String())
	if err != nil {
		return nil, err
	}
	// Parse the google Questions to DNS RRs
	questions := []dns.Question{}
	for i, c := range dohresp.Question {
		questions = append(questions, dns.Question{
			Name:   c.Name,
			Qtype:  uint16(c.Type),
			Qclass: req.Question[i].Qclass,
		})
	}

	// Parse google RRs to DNS RRs
	answers := []dns.RR{}
	for _, a := range dohresp.Answer {
		answers = append(answers, RRNewFromGoogleDohRR(a))
	}

	// Parse google RRs to DNS RRs
	authorities := []dns.RR{}
	for _, ns := range dohresp.Authority {
		authorities = append(authorities, RRNewFromGoogleDohRR(ns))
	}

	// Parse google RRs to DNS RRs
	extras := []dns.RR{}
	for _, a := range dohresp.Additional {
		extras = append(extras, RRNewFromGoogleDohRR(a))
	}
	resp = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           (dohresp.Status == 0),
			Opcode:             dns.OpcodeQuery,
			Authoritative:      false,
			Truncated:          dohresp.TC,
			RecursionDesired:   dohresp.RD,
			RecursionAvailable: dohresp.RA,
			//Zero: false,
			AuthenticatedData: dohresp.AD,
			CheckingDisabled:  dohresp.CD,
			Rcode:             int(dohresp.Status),
		},
		Compress: req.Compress,
		Question: questions,
		Answer:   answers,
		Ns:       authorities,
		Extra:    extras,
	}

	if ecs != nil {
		MsgSetECSWithAddr(resp, ecs)
	}
	return resp, nil
}

// set edns-client-subnet ip
func MsgSetECSWithAddr(m *dns.Msg, addr net.IP) {
	if addr == nil {
		return
	}
	option := m.IsEdns0()
	if option == nil {
		option = new(dns.OPT)
		option.Hdr.Name = "."
		option.Hdr.Rrtype = dns.TypeOPT

		m.Extra = append(m.Extra, option)
	}

	var ecs *dns.EDNS0_SUBNET
	for _, s := range option.Option {
		if _ecs, ok := s.(*dns.EDNS0_SUBNET); ok {
			ecs = _ecs
			break
		}
	}
	if ecs == nil {
		ecs = new(dns.EDNS0_SUBNET)
		option.Option = append(option.Option, ecs)
	}

	ecs.Code = dns.EDNS0SUBNET
	ecs.Address = addr
	if addr.To4() != nil {
		ecs.Family = 1         // 1 for IPv4 source address, 2 for IPv6
		ecs.SourceNetmask = 32 // 32 for IPV4, 128 for IPv6
	} else {
		ecs.Family = 2          // 1 for IPv4 source address, 2 for IPv6
		ecs.SourceNetmask = 128 // 32 for IPV4, 128 for IPv6
	}
	ecs.SourceScope = 0
}

// extract answer from dns msg
// FIXME: deal with name alias
func MsgExtractAnswer(msg *dns.Msg) (dns.RR, net.IP) {
	if msg == nil {
		return nil, nil
	}
	for _, ans := range msg.Answer {
		switch v := ans.(type) {
		case *dns.A:
			if v != nil && len(v.A) != 0 {
				return v, v.A
			}
		case *dns.AAAA:
			if v != nil && len(v.AAAA) != 0 {
				return v, v.AAAA
			}
		}
	}
	return nil, nil
}

// --- impl dns.RR

// Initialize a new RRGeneric from a google dns over https RR
func RRNewFromGoogleDohRR(grr google.DNSRR) dns.RR {
	var rr dns.RR

	// Build an RR header
	rrhdr := dns.RR_Header{
		Name:     grr.Name,
		Rrtype:   uint16(grr.Type),
		Class:    dns.ClassINET,
		Ttl:      uint32(grr.TTL),
		Rdlength: uint16(len(grr.Data)),
	}

	constructor, ok := dns.TypeToRR[uint16(grr.Type)]
	if ok {
		// Construct a new RR
		rr = constructor()
		*(rr.Header()) = rrhdr
		switch v := rr.(type) {
		case *dns.A:
			v.A = net.ParseIP(grr.Data)
		case *dns.AAAA:
			v.AAAA = net.ParseIP(grr.Data)
		}
	} else {
		rr = dns.RR(&dns.RFC3597{
			Hdr:   rrhdr,
			Rdata: grr.Data,
		})
	}
	return rr
}

// client for dns query
type dnsTransport struct {
	nameserver string // DNS server
	net        string // ["tcp" | "udp" | "https"]

	proxy proxy.Dialer // proxy for dns query, set to nil if don't need proxy
}

// --- impl *dnsTransport

func NewDnsTransport(nameserver, net string, _proxy proxy.Dialer) *dnsTransport {
	return &dnsTransport{nameserver: nameserver, net: net, proxy: _proxy}
}

func (dt *dnsTransport) legallySpawnQuery(domain string, qtype uint16, ecsAddr ...net.IP) (*dns.Msg, error) {
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), qtype)

	if ecsAddr != nil {
		MsgSetECSWithAddr(req, ecsAddr[0])
	}
	return dt.legallySpawnExchange(req)
}

func (dt *dnsTransport) legallySpawnExchange(req *dns.Msg) (*dns.Msg, error) {
	const spawnNum int8 = 3
	resp := make(chan *dns.Msg, spawnNum)
	lastErr := make(chan error)
	var failedTimes int32

	for range [spawnNum]struct{}{} {
		go func() {
			if r, err := dt.Exchange(req); err == nil {
				resp <- r
			} else {
				if atomic.LoadInt32(&failedTimes) == int32(spawnNum-1) {
					resp <- nil
					lastErr <- err
				} else {
					atomic.AddInt32(&failedTimes, 1)
				}
			}
		}()
	}

	if r := <-resp; r != nil {
		return r, nil
	} else {
		return nil, <-lastErr
	}
}

func (dt *dnsTransport) Exchange(req *dns.Msg) (r *dns.Msg, err error) {
	if dt.net == "https" {
		var dialc func(ctx context.Context, network, addr string) (net.Conn, error)
		if dt.proxy != nil {
			dialc = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dt.proxy.Dial(network, addr)
			}
		}
		rt := &http.Transport{
			DisableKeepAlives: true,
			DialContext:       dialc,
		}
		return MsgExchangeOverGoogleDOH(req, rt)
	}

	// --- partially copied from (*dns.Client).exchange
	const dnsTimeout time.Duration = 2 * time.Second

	var conn net.Conn
	if p := dt.proxy; p != nil {
		conn, err = p.Dial(dt.net, dt.nameserver)
	} else {
		conn, err = net.DialTimeout(dt.net, dt.nameserver, dnsTimeout)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer conn.Close()

	co := new(dns.Conn)
	co.Conn = conn

	opt := req.IsEdns0()
	// If EDNS0 is used use that for size.
	if opt != nil && opt.UDPSize() >= dns.MinMsgSize {
		co.UDPSize = opt.UDPSize()
	}

	co.SetWriteDeadline(time.Now().Add(dnsTimeout))
	if err = co.WriteMsg(req); err != nil {
		return nil, errors.WithStack(err)
	}

	co.SetReadDeadline(time.Now().Add(dnsTimeout))
	r, err = co.ReadMsg()
	if err == nil && r.Id != req.Id {
		err = dns.ErrId
	}
	return r, errors.WithStack(err)
}

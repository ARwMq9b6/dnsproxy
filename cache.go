package dnsproxy

import (
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

// ip cache, cache "ip" and transport
type ipcache struct {
	inner *cache.Cache
}

// --- impl ipcache
func NewIpcache(defaultExpiration, cleanupInterval time.Duration) ipcache {
	c := cache.New(defaultExpiration, cleanupInterval)
	return ipcache{c}
}

func (c ipcache) Add(ip string, t transport) {
	if ip == "" {
		return
	}
	c.inner.Add(ip, t, cache.DefaultExpiration)
}

func (c ipcache) Get(ip string) (transport, bool) {
	v, ok := c.inner.Get(ip)
	if ok {
		return v.(transport), true
	} else {
		return 0, false
	}
}

// domain cache, cache "domain" and dns message info
type domaincache struct {
	inner *cache.Cache
}

type domaincacheCell struct {
	ans   dns.RR    // cached answer
	trans transport // transport type for answered ips in dns message
}

// --- impl domaincache
func NewDomaincache(defaultExpiration, cleanupInterval time.Duration) domaincache {
	c := cache.New(defaultExpiration, cleanupInterval)
	return domaincache{c}
}

func (c domaincache) Add(domain string, answer dns.RR, t transport) {
	if domain == "" {
		return
	}
	if name := dns.Fqdn(domain); name != answer.Header().Name {
		answer.Header().Name = name
	}
	cell := domaincacheCell{answer, t}
	c.inner.Add(domain, &cell, cache.DefaultExpiration)
}

func (c domaincache) Get(domain string) (*domaincacheCell, bool) {
	v, ok := c.inner.Get(domain)
	if ok {
		return v.(*domaincacheCell), true
	} else {
		return nil, false
	}
}

type transport int8

const (
	_TRANS_DIRECT transport = iota
	_TRANS_PROXY
)

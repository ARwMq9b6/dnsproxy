package dnsproxy

import (
	"net"
	"sync"
)

var (
	_DEFAULT_IPCACHE     ipcache
	_DEFAULT_DOMAINCACHE domaincache

	_DEFAULT_DOMAIN_MATCHER    DomainMatcher
	_IP_MATCH_CHINESE_MAINLAND func(net.IP) bool

	_DNS_SUBNET_LOCAL_IP net.IP
	_DNS_SUBNET_PROXY_IP net.IP

	_DNSSTRANSPORT_OBEDIENT *dnsTransport
	_DNSSTRANSPORT_ABROAD   *dnsTransport
)

var _DEFAULT_GLOBALS_VALIDATOR = newGlobalsValidator()

// to determine if globals has been initialized
type globalsValidator struct {
	sync.Once
	ok bool // cached result of verification
}

// --- impl *globalsValidator
func newGlobalsValidator() *globalsValidator {
	return &globalsValidator{}
}

func (v *globalsValidator) validate() bool {
	v.Do(func() {
		if _DEFAULT_IPCACHE.inner != nil &&
			_DEFAULT_DOMAINCACHE.inner != nil &&
			_DEFAULT_DOMAIN_MATCHER != nil &&
			_IP_MATCH_CHINESE_MAINLAND != nil &&
			_DNS_SUBNET_LOCAL_IP != nil &&
			_DNS_SUBNET_LOCAL_IP != nil &&
			_DNSSTRANSPORT_OBEDIENT != nil &&
			_DNSSTRANSPORT_ABROAD != nil {
			v.ok = true
		}
	})
	return v.ok
}

// init global vars
func InitGlobals(ipc ipcache, domainc domaincache,
	dm DomainMatcher, ipMatchCHN func(net.IP) bool,
	subnetLocalIP, subnetProxyIP net.IP,
	dtObedient, dtAbroad *dnsTransport) {
	_DEFAULT_IPCACHE = ipc
	_DEFAULT_DOMAINCACHE = domainc
	_DEFAULT_DOMAIN_MATCHER = dm
	_IP_MATCH_CHINESE_MAINLAND = ipMatchCHN
	_DNS_SUBNET_LOCAL_IP = subnetLocalIP
	_DNS_SUBNET_PROXY_IP = subnetProxyIP
	_DNSSTRANSPORT_OBEDIENT = dtObedient
	_DNSSTRANSPORT_ABROAD = dtAbroad
}

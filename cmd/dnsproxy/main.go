package main

import (
	"flag"
	"net"
	"os"
	"time"

	"github.com/ARwMq9b6/dnsproxy"
	"github.com/ARwMq9b6/libgost"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

func main() {
	if err := _main(); err != nil {
		defer os.Exit(1)

		var st errors.StackTrace
		type stackTracer interface {
			StackTrace() errors.StackTrace
		}
		if e, ok := err.(stackTracer); ok {
			st = e.StackTrace()
		}
		glog.Errorf("%s%+v\n", err, st)
	}
}

func _main() error {
	// --- parse config
	var configFile string
	flag.StringVar(&configFile, "c", "./config.toml", "path of config file")
	flag.Parse()

	conf, err := newConfigRepr(configFile)
	if err != nil {
		return err
	}

	// --- init globals
	chineseDomainList, err := legallyParseDomainList(conf.ChinaList)
	if err != nil {
		return err
	}
	gfwDomainList, err := legallyParseDomainList(conf.GfwList)
	if err != nil {
		return err
	}
	dm := newDomainMatch(chineseDomainList, gfwDomainList)

	chnIPList, err := legallyParseIPNetList(conf.ChinaIPList)
	if err != nil {
		return err
	}
	ipMatchCHN := func(ip net.IP) bool {
		return ipInIPNetList(ip, chnIPList)
	}

	const (
		cacheDefaultExpiration = 5 * time.Minute
		cacheCleanupInterval   = 10 * time.Minute
	)
	ipc := dnsproxy.NewIpcache(cacheDefaultExpiration, cacheCleanupInterval)
	domainc := dnsproxy.NewDomaincache(cacheDefaultExpiration, cacheCleanupInterval)

	subnetLocalIP := net.ParseIP("114.114.114.114")
	var subnetProxyIP net.IP
	if ip := conf.Proxy.ProxyServerExternalIP; ip != "" {
		subnetProxyIP = net.ParseIP(conf.Proxy.ProxyServerExternalIP)
		if subnetProxyIP == nil {
			return errors.New("config.toml: invalid [proxy].proxy_server_external_ip")
		}
	} else {
		subnetProxyIP = net.ParseIP("8.8.8.8")
	}

	proxy, err := parseAbroadDNSProxy(conf.DNS.Abroad.Proxy)
	if err != nil {
		return err
	}
	abroadNet := "tcp"
	if conf.DNS.Abroad.EnableDNSOverHTTPS {
		abroadNet = "https"
	}
	dtAbroad := dnsproxy.NewDnsTransport(conf.DNS.Abroad.Nameserver, abroadNet, proxy)

	dtLocal := dnsproxy.NewDnsTransport(conf.DNS.Obedient.Nameserver, conf.DNS.Obedient.Net, nil)

	dnsproxy.InitGlobals(ipc, domainc, dm, ipMatchCHN,
		subnetLocalIP, subnetProxyIP, dtLocal, dtAbroad)

	// --- listen and server
	e := make(chan error)
	go func() {
		proxy := gost.NewProxyChain()
		if err := proxy.AddProxyNodeString(conf.DNS.Abroad.Proxy); err != nil {
			e <- errors.WithStack(err)
		}
		proxy.Init()
		direct := gost.NewProxyChain()
		if err := dnsproxy.ServeProxy(conf.Proxy.Listen, proxy, direct); err != nil {
			e <- err
		} else {
			e <- errors.New("ServeProxy returned without error")
		}
	}()
	go func() {
		if err := dnsproxy.ServeDNS(conf.DNS.Listen); err != nil {
			e <- err
		} else {
			e <- errors.New("ServeDNS returned without error")
		}
	}()
	return <-e
}

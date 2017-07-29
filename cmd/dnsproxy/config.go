package main

import (
	"bufio"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/ARwMq9b6/libgost"
	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
)

//go:generate go run -ldflags "-X main.CHINA_IP_LIST_PATH=china_ip_list/china_ip_list.txt -X main.ACCELERATED_DOMAIN_CHINA_PATH=dnsmasq-china-list/accelerated-domains.china.conf -X main.GFW_LIST_PATH=gfwlist/gfwlist.txt" generator.go

// ############
//  Config File
// ############
type configRepr struct {
	GfwList     string `toml:"gfw_list"`
	ChinaList   string `toml:"china_list"`
	ChinaIPList string `toml:"china_ip_list"`
	DNS         struct {
		Listen   string `toml:"listen"`
		Obedient struct {
			Nameserver string `toml:"nameserver"`
			Net        string `toml:"net"`
		} `toml:"obedient"`
		Abroad struct {
			EnableDNSOverHTTPS bool   `toml:"enable_dns_over_https"`
			Nameserver         string `toml:"nameserver"`
			Proxy              string `toml:"proxy"`
		} `toml:"abroad"`
	} `toml:"dns"`
	Proxy struct {
		Listen                string `toml:"listen"`
		ProxyServer           string `toml:"proxy_server"`
		ProxyServerExternalIP string `toml:"proxy_server_external_ip"`
	} `toml:"proxy"`
}

func newConfigRepr(fpath string) (*configRepr, error) {
	var conf configRepr
	_, err := toml.DecodeFile(fpath, &conf)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &conf, nil
}

// ###############
//  Domain Matcher
// ###############
type domainMatch struct {
	chineseList []string
	gfwList     []string
}

func newDomainMatch(chineseList, gfwList []string) *domainMatch {
	return &domainMatch{chineseList: chineseList, gfwList: gfwList}
}

func (match *domainMatch) MatchGFW(domain string) bool {
	return domainMatchList(domain, match.gfwList)
}

func (match *domainMatch) MatchObedient(domain string) bool {
	return domainMatchList(domain, match.chineseList)
}

func domainMatchList(domain string, domainList []string) bool {
	for _, _domain := range domainList {
		if _domain == domain || strings.HasSuffix(domain, "."+_domain) {
			return true
		}
	}
	return false
}

// #########
//  IP util
// #########
func ipInIPNetList(ip net.IP, ipnets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, ipNet := range ipnets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// ############
//  Parse TXTs
// ############

// parse china_domain_list.txt or gfw_domain_list.txt to domain list
func legallyParseDomainList(fpath string) ([]string, error) {
	file, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	list := strings.Split(string(file), "\n")
	if len(list) == 0 {
		return nil, errors.New("empty domain list")
	}
	return list, nil
}

// parse china_ip_list.txt to IPNet list
func legallyParseIPNetList(fpath string) ([]*net.IPNet, error) {
	var ipNets []*net.IPNet

	file, err := os.Open(fpath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		_, ipn, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			return nil, errors.WithStack(err)
		}
		ipNets = append(ipNets, ipn)
	}
	if len(ipNets) == 0 {
		return nil, errors.New("empty IP Network list")
	}

	return ipNets, nil
}

// #################
//  Abroad DNS Proxy
// #################

func parseAbroadDNSProxy(proxyserver string) (proxy.Dialer, error) {
	node, err := gost.ParseProxyNode(proxyserver)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	switch node.Protocol {
	case "socks5":
		if !strings.Contains(node.Addr, ":") {
			return nil, errors.New("lack of addr port")
		}
		d, err := proxy.SOCKS5("tcp", node.Addr, nil, proxy.Direct)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return d, nil
	default:
		pc := gost.NewProxyChain(node)
		return newGostProxyChain(pc), nil
	}
}

// gostProxyChain implement proxy.Dialer
type gostProxyChain struct {
	inner *gost.ProxyChain
}

func newGostProxyChain(pc *gost.ProxyChain) gostProxyChain {
	return gostProxyChain{inner: pc}
}

func (p gostProxyChain) Dial(network, addr string) (net.Conn, error) {
	return p.inner.Dial(addr)
}

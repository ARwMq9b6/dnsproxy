package dnsproxy

import (
	"net"
	"strings"

	"github.com/golang/glog"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

func ServeDNS(laddr string) error {
	if ok := _DEFAULT_GLOBALS_VALIDATOR.validate(); !ok {
		return errors.New("global vars are uninitialized")
	}
	return serveDNS(laddr)
}

func serveDNS(laddr string) error {
	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", handleDnsRequest)

	e := make(chan error)
	for _, _net := range [...]string{"udp", "tcp"} {
		srv := &dns.Server{Addr: laddr, Net: _net, Handler: serveMux}
		go func(srv *dns.Server) {
			e <- srv.ListenAndServe()
		}(srv)
	}
	return <-e
}

func handleDnsRequest(w dns.ResponseWriter, req *dns.Msg) {
	// 判断请求的域名是否在 domain cache 中
	//	-> 是 -> 直接返回 cache 中内容
	//	-> 否 ->
	//	 -> 判断域名是否在 GFW list 中
	//	 	-> 是 -> 将使用代理访问这个域名 -> 因此使用 EDNS0 proxy + abroad dns server 查询 IP
	//		-> 否
	//			-> 判断域名是否在 obedient list 中
	//				-> 是
	//					-> 将直连这个域名 -> 因此使用 chinese dns server 解析
	//				-> 否
	//			 		—> 使用随便一个中国 IP + abroad dns server 解析
	//						-> 成功
	//							-> 判断是否返回中国 IP
	//								-> 是 -> 返回中国 IP 表示这个域名是 obedient -> 使用中国的 DNS 服务器再查一边: china dns sever
	//								-> 否 -> 使用 EDNS0 Abroad + abroad dns server 解析
	//						-> 失败 -> 使用 china dns server 解析
	resp, err := func() (*dns.Msg, error) {
		var domain string
		quesFqdn := req.Question[0].Name

		if strings.HasSuffix(quesFqdn, `.DHCP\ HOST.`) {
			return MsgNewReplyFromReq(req), nil
		} else {
			domain = quesFqdn[:len(quesFqdn)-1]
			if item, ok := _DEFAULT_DOMAINCACHE.Get(domain); ok {
				return MsgNewReplyFromReq(req, item.ans), nil
			}
		}

		var matchGfw bool
		var matchObedient bool
		matchGfw = _DEFAULT_DOMAIN_MATCHER.MatchGFW(domain)
		if !matchGfw {
			matchObedient = _DEFAULT_DOMAIN_MATCHER.MatchObedient(domain)
		}

		switch {
		case matchGfw: // domain is in gfw blacklist
			MsgSetECSWithAddr(req, _DNS_SUBNET_PROXY_IP)
			resp, err := _DNSSTRANSPORT_ABROAD.legallySpawnExchange(req)
			if err != nil {
				return nil, err
			}
			if ans, ip := MsgExtractAnswer(resp); ans != nil {
				_DEFAULT_DOMAINCACHE.Add(domain, ans, _TRANS_PROXY)
				_DEFAULT_IPCACHE.Add(ip.String(), _TRANS_PROXY)
			}
			return resp, nil
		case matchObedient: // domain is in gfw whitelist
			resp, err := _DNSSTRANSPORT_OBEDIENT.legallySpawnExchange(req)
			if ans, ip := MsgExtractAnswer(resp); ans != nil && err == nil {
				_DEFAULT_DOMAINCACHE.Add(domain, ans, _TRANS_DIRECT)
				_DEFAULT_IPCACHE.Add(ip.String(), _TRANS_DIRECT)
			} else {
				// retry with abroad dns server
				MsgSetECSWithAddr(req, _DNS_SUBNET_LOCAL_IP)
				resp, err = _DNSSTRANSPORT_ABROAD.legallySpawnExchange(req)
				if err != nil {
					return nil, err
				}
				// do not add to cache
			}
			return resp, nil
		default: // unknown domain
			// async abroad query with remote ip
			abroadQueryWithRemoteIPReq := req.Copy()
			awaitAbroadQueryWithRemoteResp := make(chan *dns.Msg, 1)
			go func() {
				remoteIP := _DNS_SUBNET_PROXY_IP
				MsgSetECSWithAddr(abroadQueryWithRemoteIPReq, remoteIP)
				resp, _ := _DNSSTRANSPORT_ABROAD.legallySpawnExchange(abroadQueryWithRemoteIPReq)

				awaitAbroadQueryWithRemoteResp <- resp
			}()

			// abroad query with local ip
			abroadQueryWithLocalIPReq := req.Copy()
			var abroadQueryWithLocalSucceed bool
			var abroadQueryWithLocalAns dns.RR
			var abroadQueryWithLocalAnsIP net.IP

			localIP := _DNS_SUBNET_LOCAL_IP
			MsgSetECSWithAddr(abroadQueryWithLocalIPReq, localIP)
			abroadQueryWithLocalResp, err := _DNSSTRANSPORT_ABROAD.legallySpawnExchange(abroadQueryWithLocalIPReq)
			if ans, ip := MsgExtractAnswer(abroadQueryWithLocalResp); err == nil && ans != nil {
				abroadQueryWithLocalSucceed = abroadQueryWithLocalResp.Rcode == dns.RcodeSuccess
				abroadQueryWithLocalAns = ans
				abroadQueryWithLocalAnsIP = ip
			}
			if abroadQueryWithLocalSucceed { // succeeded to abroad query with local ip
				var resp = abroadQueryWithLocalResp
				var ans = abroadQueryWithLocalAns
				var ip = abroadQueryWithLocalAnsIP
				var trans transport

				if i := abroadQueryWithLocalAnsIP.To4(); i != nil &&
					_IP_MATCH_CHINESE_MAINLAND(i) {
					// is Chinese mainland ipv4
					trans = _TRANS_DIRECT
					// try to query obedient dns server to improve `a` quality
					_resp, err := _DNSSTRANSPORT_OBEDIENT.legallySpawnExchange(req)
					if _ans, _ip := MsgExtractAnswer(_resp); err == nil && _ans != nil {
						resp = _resp
						ans = _ans
						ip = _ip
					}
				} else {
					// ipv6 or abroad ipv4
					trans = _TRANS_PROXY
					// try to improve resp with the result of async abroad query with remote ip
					_resp := <-awaitAbroadQueryWithRemoteResp
					_ans, _ip := MsgExtractAnswer(_resp)
					if _ans != nil {
						resp = _resp
						ans = _ans
						ip = _ip
					}
				}
				_DEFAULT_DOMAINCACHE.Add(domain, ans, trans)
				_DEFAULT_IPCACHE.Add(ip.String(), trans)
				return resp, nil
			} else { // failed to abroad query with local ip
				// try to query with obedient dns server
				resp, err := _DNSSTRANSPORT_OBEDIENT.legallySpawnExchange(req)
				if err != nil { // all queries failed
					return nil, err
				}
				if ans, ip := MsgExtractAnswer(resp); ans != nil {
					var trans transport
					if ip.To4() != nil && _IP_MATCH_CHINESE_MAINLAND(ip) {
						// is Chinese mainland ipv4
						trans = _TRANS_DIRECT
					} else {
						// ipv6 or abroad ipv4
						trans = _TRANS_PROXY
					}
					_DEFAULT_DOMAINCACHE.Add(domain, ans, trans)
					_DEFAULT_IPCACHE.Add(ip.String(), trans)
				}
				return resp, nil
			}
		}
	}()
	if err != nil {
		goto ERR
	}
	if err = w.WriteMsg(resp); err != nil {
		goto ERR
	}
	return
ERR:
	var st errors.StackTrace
	type stackTracer interface {
		StackTrace() errors.StackTrace
	}
	if e, ok := err.(stackTracer); ok {
		st = e.StackTrace()
	}
	glog.Warningf("%s%+v\n", err, st)
}

package dnsproxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ARwMq9b6/libgost"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

func ServeProxy(laddr string, proxy, direct *gost.ProxyChain) error {
	if ok := _DEFAULT_GLOBALS_VALIDATOR.validate(); !ok {
		return errors.New("global vars are uninitialized")
	}
	return serveProxy(laddr, proxy, direct)
}

func serveProxy(laddr string, proxy, direct *gost.ProxyChain) error {
	serverProxy := gost.NewProxyServer(gost.ProxyNode{}, proxy, nil)
	serverDirect := gost.NewProxyServer(gost.ProxyNode{}, direct, nil)
	servers := map[transport]*gost.ProxyServer{
		_TRANS_PROXY:  serverProxy,
		_TRANS_DIRECT: serverDirect,
	}

	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return errors.WithStack(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			glog.Error(err)
		}
		go func(conn net.Conn) {
			if err := handleProxyConn(conn, serverProxy, serverDirect, servers); err != nil {
				var st errors.StackTrace
				type stackTracer interface {
					StackTrace() errors.StackTrace
				}
				if e, ok := err.(stackTracer); ok {
					st = e.StackTrace()
				}
				glog.Errorf("%s%+v\n", err, st)
			}
		}(conn)
	}
}

func handleProxyConn(conn net.Conn, serverProxy, serverDirect *gost.ProxyServer, servers map[transport]*gost.ProxyServer) error {
	defer conn.Close()

	b := make([]byte, gost.MediumBufferSize)

	n, err := io.ReadAtLeast(conn, b, 2)
	if err != nil && err != io.EOF {
		return errors.WithStack(err)
	}

	var reqer requester
	conn = newConnLeftAppendReader(conn, bytes.NewReader(b[:n]))
	if b[0] == gosocks5.Ver5 {
		conn = gosocks5.ServerConn(conn, serverProxy.Selector)
		req, err := gosocks5.ReadRequest(conn)
		if err != nil {
			return errors.WithStack(err)
		}
		reqer = newSocks5Request(req, conn)
	} else {
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return errors.WithStack(err)
		}
		reqer = newHTTPRequest(req, conn)
	}

	// switch req.Addr.Type:
	// case AddrIPv4, typ == AddrIPv6:
	//	-> 去 DNS 缓存里找是直连还是代理
	//		—> 找到
	//			-> 根据得到的策略执行直连或代理
	//		-> 未找到
	// 			-> 中国 IP 直连，外国 IP 代理
	// case AddrDomain:
	//	-> 尝试在缓存中找域名信息
	//		-> 找到 -> 根据策略进行直连或代理
	//		-> 未找到
	//			 -> 判断域名是否在 gfw list 中
	//			 	-> 是
	//					-> 直接代理（不 DNS 解析）
	//				-> 否
	//					-> 检查域名是否在 china ip list 中
	//						-> 是 -> 使用 china dns sever 解析 -> 直连
	//						-> 否
	//							-> 使用 edns0 china + abroad dns server 解析
	//								-> 成功
	//									-> 判断是否返回中国 IP
	//										-> 是
	//		 									-> 使用 china dns sever 解析 -> 直连
	//										-> 否 -> 直接代理（不 DNS 解析）
	//								-> 失败
	//									—> 使用 china dns server 解析
	//										-> 判断是否返回中国 IP
	//											-> 是 -> 直连
	//											-> 否 -> 直接代理（不 DNS 解析）
	ps, err := func() (*gost.ProxyServer, error) {
		switch reqer.getAddrType() {
		case AddrIPv4, AddrIPv6:
			host := reqer.getHostName()
			trans, ok := _DEFAULT_IPCACHE.Get(host)
			if !ok {
				ip := net.ParseIP(host)

				if ip.To4() != nil && _IP_MATCH_CHINESE_MAINLAND(ip) {
					trans = _TRANS_DIRECT
				} else {
					trans = _TRANS_PROXY
				}
				_DEFAULT_IPCACHE.Add(host, trans)
			}
			return servers[trans], nil
		case AddrDomain:
			domain := reqer.getHostName()
			// try to get domain info from cache
			if item, ok := _DEFAULT_DOMAINCACHE.Get(domain); ok {
				if item.trans == _TRANS_DIRECT {
					switch v := item.ans.(type) {
					case *dns.A:
						reqer.setRedirect(v.A)
					case *dns.AAAA:
						reqer.setRedirect(v.AAAA)
					default:
						return nil, errors.New("unreachable!")
					}
				}
				return servers[item.trans], nil
			}
			matchGfw := _DEFAULT_DOMAIN_MATCHER.MatchGFW(domain)
			matchObedient := _DEFAULT_DOMAIN_MATCHER.MatchObedient(domain)
			switch {
			case matchGfw:
				return serverProxy, nil
			case matchObedient:
				resp, err := _DNSSTRANSPORT_OBEDIENT.legallySpawnQuery(domain, dns.TypeA)
				if ans, ip := MsgExtractAnswer(resp); err == nil && ans != nil {
					reqer.setRedirect(ip)

					_DEFAULT_IPCACHE.Add(ip.String(), _TRANS_DIRECT)
					_DEFAULT_DOMAINCACHE.Add(domain, ans, _TRANS_DIRECT)
				}
				return serverDirect, nil
			default:
				// abroad query with local ip
				resp, err := _DNSSTRANSPORT_ABROAD.legallySpawnQuery(domain, dns.TypeA, _DNS_SUBNET_LOCAL_IP)
				if ans, ip := MsgExtractAnswer(resp); err == nil && ans != nil {
					// succeeded to abroad query with local ip
					var trans transport
					if ip.To4() != nil && _IP_MATCH_CHINESE_MAINLAND(ip) {
						// is Chinese mainland ipv4
						trans = _TRANS_DIRECT
						// try to query obedient dns server to improve `a` quality
						resp, err = _DNSSTRANSPORT_OBEDIENT.legallySpawnQuery(domain, dns.TypeA)
						if _ans, _ip := MsgExtractAnswer(resp); err == nil && _ans != nil {
							ans = _ans
							ip = _ip
						}
						reqer.setRedirect(ip)
					} else { // ipv6 or abroad ipv4
						trans = _TRANS_PROXY
						// do not change the host name or addr type
					}
					_DEFAULT_DOMAINCACHE.Add(domain, ans, trans)
					_DEFAULT_IPCACHE.Add(ip.String(), trans)
					return servers[trans], nil
				} else { // failed to abroad query with local ip
					// try to query with obedient dns server
					resp, err = _DNSSTRANSPORT_OBEDIENT.legallySpawnQuery(domain, dns.TypeA)
					if ans, ip := MsgExtractAnswer(resp); err == nil && ans != nil {
						var trans transport
						if ip.To4() != nil && _IP_MATCH_CHINESE_MAINLAND(ip) {
							trans = _TRANS_DIRECT

							reqer.setRedirect(ip)
						} else { // ipv6 or abroad ipv4
							trans = _TRANS_PROXY
						}
						_DEFAULT_IPCACHE.Add(ip.String(), trans)
						_DEFAULT_DOMAINCACHE.Add(domain, ans, trans)

						return servers[trans], nil
					} else {
						// all queries failed
						return serverProxy, nil
					}
				}
			}
		}
		return nil, nil
	}()
	if err != nil {
		return err
	}
	reqer.setProxyServer(ps)
	reqer.exec()
	return nil
}

const (
	AddrIPv4   uint8 = gosocks5.AddrIPv4
	AddrDomain       = gosocks5.AddrDomain
	AddrIPv6         = gosocks5.AddrIPv6
)

type requester interface {
	getHostName() string
	getAddrType() uint8

	setRedirect(ip net.IP)
	setProxyServer(*gost.ProxyServer)

	exec()
}

type socks5Request struct {
	req   *gosocks5.Request
	conn  net.Conn
	proxy *gost.ProxyServer
}

func newSocks5Request(req *gosocks5.Request, conn net.Conn) *socks5Request {
	return &socks5Request{req: req, conn: conn, proxy: nil}
}

func (r *socks5Request) setRedirect(ip net.IP) {
	var addrType uint8
	if ip.To4() != nil {
		addrType = AddrIPv4
	} else {
		addrType = AddrIPv4
	}
	r.req.Addr.Type = addrType
	r.req.Addr.Host = ip.String()
}

func (r *socks5Request) getHostName() string {
	return r.req.Addr.Host
}

func (r *socks5Request) getAddrType() uint8 {
	return r.req.Addr.Type
}

func (r *socks5Request) setProxyServer(ps *gost.ProxyServer) {
	r.proxy = ps
}

func (r *socks5Request) exec() {
	gost.NewSocks5Server(r.conn, r.proxy).HandleRequest(r.req)
}

type httpRequest struct {
	req   *http.Request
	conn  net.Conn
	proxy *gost.ProxyServer
}

func newHTTPRequest(req *http.Request, conn net.Conn) *httpRequest {
	return &httpRequest{req: req, conn: conn, proxy: nil}
}

func (r *httpRequest) setRedirect(_ net.IP) {
	// TODO: make it come true
}

func (r *httpRequest) getHostName() string {
	return r.req.URL.Hostname()
}

func (r *httpRequest) getAddrType() uint8 {
	if ip := net.ParseIP(r.req.URL.Hostname()); ip != nil {
		if ip.To4() != nil {
			return AddrIPv4
		}
		return AddrIPv6
	}
	return AddrDomain
}

func (r *httpRequest) setProxyServer(ps *gost.ProxyServer) {
	r.proxy = ps
}

func (r *httpRequest) exec() {
	gost.NewHttpServer(r.conn, r.proxy).HandleRequest(r.req)
}

type connLeftAppendReader struct {
	r    io.Reader
	reof bool // `r` match io.EOF

	conn net.Conn
}

func newConnLeftAppendReader(conn net.Conn, r io.Reader) *connLeftAppendReader {
	return &connLeftAppendReader{r: r, conn: conn}
}

// --- impl net.Conn for *connLeftAppendReader {
func (cc *connLeftAppendReader) Read(b []byte) (n int, err error) {
	if !cc.reof {
		n, err = cc.r.Read(b)
		if err == nil {
			return n, nil
		}
		if err == io.EOF {
			cc.reof = true
			return n, nil
		}
		return n, err
	}
	return cc.conn.Read(b)
}

func (cc *connLeftAppendReader) Write(b []byte) (n int, err error) {
	return cc.conn.Write(b)
}

func (cc *connLeftAppendReader) Close() error {
	return cc.conn.Close()
}

func (cc *connLeftAppendReader) LocalAddr() net.Addr {
	return cc.conn.LocalAddr()
}

func (cc *connLeftAppendReader) RemoteAddr() net.Addr {
	return cc.conn.RemoteAddr()
}

func (cc *connLeftAppendReader) SetDeadline(t time.Time) error {
	return cc.conn.SetDeadline(t)
}

func (cc *connLeftAppendReader) SetReadDeadline(t time.Time) error {
	return cc.conn.SetReadDeadline(t)
}

func (cc *connLeftAppendReader) SetWriteDeadline(t time.Time) error {
	return cc.conn.SetWriteDeadline(t)
}

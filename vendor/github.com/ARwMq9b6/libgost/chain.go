package gost

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Proxy chain holds a list of proxy nodes
type ProxyChain struct {
	nodes          []ProxyNode
	lastNode       *ProxyNode
	http2NodeIndex int
	http2Enabled   bool
	http2Client    *http.Client
	kcpEnabled     bool
	kcpConfig      *KCPConfig
	kcpSession     *KCPSession
	kcpMutex       sync.Mutex
}

func NewProxyChain(nodes ...ProxyNode) *ProxyChain {
	chain := &ProxyChain{nodes: nodes, http2NodeIndex: -1}
	return chain
}

func (c *ProxyChain) AddProxyNode(node ...ProxyNode) {
	c.nodes = append(c.nodes, node...)
}

func (c *ProxyChain) AddProxyNodeString(snode ...string) error {
	for _, sn := range snode {
		node, err := ParseProxyNode(sn)
		if err != nil {
			return err
		}
		c.AddProxyNode(node)
	}
	return nil
}

func (c *ProxyChain) Nodes() []ProxyNode {
	return c.nodes
}

func (c *ProxyChain) GetNode(index int) *ProxyNode {
	if index < len(c.nodes) {
		return &c.nodes[index]
	}
	return nil
}

func (c *ProxyChain) SetNode(index int, node ProxyNode) {
	if index < len(c.nodes) {
		c.nodes[index] = node
	}
}

// Init initialize the proxy chain.
// KCP will be enabled if the first proxy node is KCP proxy (transport == kcp).
// HTTP2 will be enabled when at least one HTTP2 proxy node (scheme == http2) is present.
//
// NOTE: Should be called immediately when proxy nodes are ready.
func (c *ProxyChain) Init() {
	length := len(c.nodes)
	if length == 0 {
		return
	}

	c.lastNode = &c.nodes[length-1]

	// HTTP2 restrict: HTTP2 will be enabled when at least one HTTP2 proxy node is present.
	for i, node := range c.nodes {
		if node.Transport == "http2" {
			glog.V(LINFO).Infoln("HTTP2 is enabled")
			cfg := &tls.Config{
				InsecureSkipVerify: node.insecureSkipVerify(),
				ServerName:         node.serverName,
			}
			c.http2NodeIndex = i
			c.initHttp2Client(cfg, c.nodes[:i]...)
			break // shortest chain for HTTP2
		}
	}

	for i, node := range c.nodes {
		if node.Transport == "kcp" && i > 0 {
			glog.Fatal("KCP must be the first node in the proxy chain")
		}
	}

	if c.nodes[0].Transport == "kcp" {
		glog.V(LINFO).Infoln("KCP is enabled")
		c.kcpEnabled = true
		config, err := ParseKCPConfig(c.nodes[0].Get("c"))
		if err != nil {
			glog.V(LWARNING).Infoln("[kcp]", err)
		}
		if config == nil {
			config = DefaultKCPConfig
		}
		if c.nodes[0].Users != nil {
			config.Crypt = c.nodes[0].Users[0].Username()
			config.Key, _ = c.nodes[0].Users[0].Password()
		}
		c.kcpConfig = config
		return
	}
}

func (c *ProxyChain) KCPEnabled() bool {
	return c.kcpEnabled
}

func (c *ProxyChain) Http2Enabled() bool {
	return c.http2Enabled
}

func (c *ProxyChain) initHttp2Client(config *tls.Config, nodes ...ProxyNode) {
	if c.http2NodeIndex < 0 || c.http2NodeIndex >= len(c.nodes) {
		return
	}
	http2Node := c.nodes[c.http2NodeIndex]

	tr := http2.Transport{
		TLSClientConfig: config,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			// replace the default dialer with our proxy chain.
			conn, err := c.dialWithNodes(false, http2Node.Addr, nodes...)
			if err != nil {
				return conn, err
			}
			conn = tls.Client(conn, cfg)

			// enable HTTP2 ping-pong
			pingIntvl, _ := strconv.Atoi(http2Node.Get("ping"))
			if pingIntvl > 0 {
				enablePing(conn, time.Duration(pingIntvl)*time.Second)
			}

			return conn, nil
		},
	}
	c.http2Client = &http.Client{Transport: &tr}
	c.http2Enabled = true

}

func enablePing(conn net.Conn, interval time.Duration) {
	if conn == nil || interval == 0 {
		return
	}

	glog.V(LINFO).Infoln("[http2] ping enabled, interval:", interval)
	go func() {
		t := time.NewTicker(interval)
		var framer *http2.Framer
		for {
			select {
			case <-t.C:
				if framer == nil {
					framer = http2.NewFramer(conn, conn)
				}

				var p [8]byte
				rand.Read(p[:])
				err := framer.WritePing(false, p)
				if err != nil {
					t.Stop()
					framer = nil
					glog.V(LWARNING).Infoln("[http2] ping:", err)
					return
				}
			}
		}
	}()
}

// Connect to addr through proxy chain
func (c *ProxyChain) Dial(addr string) (net.Conn, error) {
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	return c.dialWithNodes(true, addr, c.nodes...)
}

// GetConn initializes a proxy chain connection,
// if no proxy nodes on this chain, it will return error
func (c *ProxyChain) GetConn() (net.Conn, error) {
	nodes := c.nodes
	if len(nodes) == 0 {
		return nil, ErrEmptyChain
	}

	if c.Http2Enabled() {
		nodes = nodes[c.http2NodeIndex+1:]
		if len(nodes) == 0 {
			header := make(http.Header)
			header.Set("Proxy-Switch", "gost") // Flag header to indicate server to switch to HTTP2 transport mode
			conn, err := c.getHttp2Conn(header)
			if err != nil {
				return nil, err
			}
			http2Node := c.nodes[c.http2NodeIndex]
			if http2Node.Transport == "http2" {
				http2Node.Transport = "h2"
			}
			if http2Node.Protocol == "http2" {
				http2Node.Protocol = "socks5" // assume it as socks5 protocol, so we can do much more things.
			}
			pc := NewProxyConn(conn, http2Node)
			if err := pc.Handshake(); err != nil {
				conn.Close()
				return nil, err
			}
			return pc, nil
		}
	}
	return c.travelNodes(true, nodes...)
}

func (c *ProxyChain) dialWithNodes(withHttp2 bool, addr string, nodes ...ProxyNode) (conn net.Conn, err error) {
	if len(nodes) == 0 {
		return net.DialTimeout("tcp", addr, DialTimeout)
	}

	if withHttp2 && c.Http2Enabled() {
		nodes = nodes[c.http2NodeIndex+1:]
		if len(nodes) == 0 {
			return c.http2Connect(addr)
		}
	}
	pc, err := c.travelNodes(withHttp2, nodes...)
	if err != nil {
		return
	}
	if err = pc.Connect(addr); err != nil {
		pc.Close()
		return
	}
	conn = pc
	return
}

func (c *ProxyChain) travelNodes(withHttp2 bool, nodes ...ProxyNode) (conn *ProxyConn, err error) {
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
			conn = nil
		}
	}()

	var cc net.Conn
	node := nodes[0]

	if withHttp2 && c.Http2Enabled() {
		cc, err = c.http2Connect(node.Addr)
	} else if node.Transport == "kcp" {
		cc, err = c.getKCPConn()
	} else {
		cc, err = net.DialTimeout("tcp", node.Addr, DialTimeout)
	}
	if err != nil {
		return
	}
	setKeepAlive(cc, KeepAliveTime)

	pc := NewProxyConn(cc, node)
	conn = pc
	if err = pc.Handshake(); err != nil {
		return
	}

	for _, node := range nodes[1:] {
		if err = conn.Connect(node.Addr); err != nil {
			return
		}
		pc := NewProxyConn(conn, node)
		conn = pc
		if err = pc.Handshake(); err != nil {
			return
		}
	}
	return
}

func (c *ProxyChain) initKCPSession() (err error) {
	c.kcpMutex.Lock()
	defer c.kcpMutex.Unlock()

	if c.kcpSession == nil || c.kcpSession.IsClosed() {
		glog.V(LINFO).Infoln("[kcp] new kcp session")
		c.kcpSession, err = DialKCP(c.nodes[0].Addr, c.kcpConfig)
	}
	return
}

func (c *ProxyChain) getKCPConn() (conn net.Conn, err error) {
	if !c.KCPEnabled() {
		return nil, errors.New("KCP is not enabled")
	}

	if err = c.initKCPSession(); err != nil {
		return nil, err
	}
	return c.kcpSession.GetConn()
}

// Initialize an HTTP2 transport if HTTP2 is enabled.
func (c *ProxyChain) getHttp2Conn(header http.Header) (net.Conn, error) {
	if !c.Http2Enabled() {
		return nil, errors.New("HTTP2 is not enabled")
	}
	http2Node := c.nodes[c.http2NodeIndex]
	pr, pw := io.Pipe()

	if header == nil {
		header = make(http.Header)
	}

	req := http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: http2Node.Addr},
		Header:        header,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Body:          pr,
		Host:          http2Node.Addr,
		ContentLength: -1,
	}
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(&req, false)
		glog.Infoln(string(dump))
	}
	resp, err := c.http2Client.Do(&req)
	if err != nil {
		return nil, err
	}
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpResponse(resp, false)
		glog.Infoln(string(dump))
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errors.New(resp.Status)
	}
	conn := &http2Conn{r: resp.Body, w: pw}
	conn.remoteAddr, _ = net.ResolveTCPAddr("tcp", http2Node.Addr)
	return conn, nil
}

// Use HTTP2 as transport to connect target addr.
//
// BUG: SOCKS5 is ignored, only HTTP supported
func (c *ProxyChain) http2Connect(addr string) (net.Conn, error) {
	if !c.Http2Enabled() {
		return nil, errors.New("HTTP2 is not enabled")
	}
	http2Node := c.nodes[c.http2NodeIndex]

	header := make(http.Header)
	header.Set("Gost-Target", addr) // Flag header to indicate the address that server connected to
	if http2Node.Users != nil {
		header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(http2Node.Users[0].String())))
	}
	return c.getHttp2Conn(header)
}

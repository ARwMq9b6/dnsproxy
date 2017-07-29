package google

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

const DEFAULT_DNS_SERVER = "https://dns.google.com/resolve"

// --- partially copied from https://github.com/wrouesnel/dns-over-https-proxy/blob/master/dns-over-https-proxy.go
// Rough translation of the Google DNS over HTTP API
type RespRepr struct {
	Status             int32         `json:"Status,omitempty"`
	TC                 bool          `json:"TC,omitempty"`
	RD                 bool          `json:"RD,omitempty"`
	RA                 bool          `json:"RA,omitempty"`
	AD                 bool          `json:"AD,omitempty"`
	CD                 bool          `json:"CD,omitempty"`
	Question           []DNSQuestion `json:"Question,omitempty"`
	Answer             []DNSRR       `json:"Answer,omitempty"`
	Authority          []DNSRR       `json:"Authority,omitempty"`
	Additional         []DNSRR       `json:"Additional,omitempty"`
	Edns_client_subnet string        `json:"edns_client_subnet,omitempty"`
	Comment            string        `json:"Comment,omitempty"`
}

type DNSQuestion struct {
	Name string `json:"name,omitempty"`
	Type int32  `json:"type,omitempty"`
}

type DNSRR struct {
	Name string `json:"name,omitempty"`
	Type int32  `json:"type,omitempty"`
	TTL  int32  `json:"TTL,omitempty"`
	Data string `json:"data,omitempty"`
}

// --- impl RespRepr

// Performs a DNS over HTTPS query
// qtype: The resource records type to be requested, such as dns.TypeTA
// name: Domian name to resolve. Example: `twitter.com`, `twitter.com.`
// ecs(optional): edns client subnet, `0.0.0.0/0` as default if empty. Example: `0.0.0.0/0`
func Query(rt http.RoundTripper, qtype uint16, name string, ecs ...string) (*RespRepr, error) {
	vs := make(url.Values, 3)
	vs.Add("name", name)
	vs.Add("type", fmt.Sprintf("%v", qtype))
	if ecs != nil {
		_ecs := ecs[0]
		if _ecs == "" {
			_ecs = "0.0.0.0/0"
		}
		vs.Add("edns_client_subnet", _ecs)
	}

	_url := fmt.Sprintf("%s?%s", DEFAULT_DNS_SERVER, vs.Encode())
	req, err := http.NewRequest(http.MethodGet, _url, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse the JSON response
	repr := new(RespRepr)
	d := json.NewDecoder(resp.Body)
	err = d.Decode(repr)
	return repr, errors.WithStack(err)
}

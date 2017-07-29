// +build ignore

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

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

		fmt.Printf("%s%+v\n", err, st)
	}
}

var (
	// path of `china_ip_list.txt`
	CHINA_IP_LIST_PATH string
	// path of `accelerated-domains.china.conf`
	ACCELERATED_DOMAIN_CHINA_PATH string
	// path of `gfwlist.txt`
	GFW_LIST_PATH string
)

func _main() error {
	// copy `./config.toml` and `china_ip_list/china_ip_list.txt` to folder target

	// +build go1.9
	//
	// ```
	// type dst = string
	// type src = string
	// copys := map[dst]src{
	//	 "target/config.toml": "./config.toml",
	//	 "target/china_ip_list.txt": CHINA_IP_LIST_PATH,
	// }
	// ```

	copys := map[string]string{
		"target/config.toml":       "./config.toml",
		"target/china_ip_list.txt": CHINA_IP_LIST_PATH,
	}
	for dst, src := range copys {
		data, err := ioutil.ReadFile(src)
		if err != nil {
			return errors.WithStack(err)
		}
		if err = ioutil.WriteFile(dst, data, 0644); err != nil {
			return errors.WithStack(err)
		}
	}

	// generate china-list.txt and gfw-list.txt
	for _, generator := range [...]func() error{
		generateGFWDomainList,
		generateChinaDomainList,
	} {
		if err := generator(); err != nil {
			return err
		}
	}
	return nil
}

// generate gfw_domain_list.txt
func generateGFWDomainList() error {
	// read from `GFW_LIST_PATH`
	b, err := ioutil.ReadFile(GFW_LIST_PATH)
	if err != nil {
		return errors.WithStack(err)
	}

	b, err = base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return errors.WithStack(err)
	}
	content := string(b)

	re := regexp.MustCompile(`.*?((:?(:?(:?[a-zA-Z])|(:?[a-zA-Z][a-zA-Z])|(:?[a-zA-Z][0-9])|(:?[0-9][a-zA-Z])|(:?[a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.)+(:?xn--[a-z0-9-]+|[a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})).*`)

	end := strings.Index(content, "Whitelist Start")
	matches := re.FindAllStringSubmatch(content[:end], -1)
	mLen := len(matches)
	if mLen == 0 {
		return errors.New("generate gfw domains: got nothing")
	}
	gfwItems := make(map[string]struct{})
	for _, groups := range matches {
		gfwItems[groups[1]] = struct{}{}
	}

	// write to `gfw-list.txt`
	file, err := os.Create("target/gfw_domain_list.txt")
	if err != nil {
		return err
	}
	defer file.Close()

	for item, _ := range gfwItems {
		file.Write(append([]byte(item), 0x0A))
	}
	return nil
}

// generate china_domain_list.txt
func generateChinaDomainList() error {
	// read from `ACCELERATED_DOMAIN_CHINA_PATH`
	content, err := ioutil.ReadFile(ACCELERATED_DOMAIN_CHINA_PATH)
	if err != nil {
		return errors.WithStack(err)
	}
	re := regexp.MustCompile(`server=/(.+)/.+`)
	subMatch := re.FindAllSubmatch(content, -1)

	domainList := make([][]byte, 0, len(subMatch))
	for _, s := range subMatch {
		domainList = append(domainList, s[1])
	}
	if len(domainList) == 0 {
		return errors.New("generate china domains: got nothing")
	}

	// write to `china-list.txt`
	data := bytes.Join(domainList, []byte{0x0A})
	return ioutil.WriteFile("target/china_domain_list.txt", data, 0644)
}

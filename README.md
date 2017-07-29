# dnsproxy

DNS 服务器 + 代理服务器

作为 DNS 服务器使用时

- [中国大陆的域名](https://github.com/felixonmars/dnsmasq-china-list) 通过国内 DNS 服务器查询
- [gfwlist](https://github.com/gfwlist/gfwlist) 中的域名通过代理服务器向国外 DNS 服务器查询
- 不在以上两者中的域名：先通过代理服务器向国外 DNS 服务器查询，如果得到中国大陆 IP 则再通过国内 DNS 服务器查询一次以试图获取更好的 IP 质量

作为代理服务器使用时

- [中国大陆的域名](https://github.com/felixonmars/dnsmasq-china-list) 直连
- [gfwlist](https://github.com/gfwlist/gfwlist) 中的域名通过代理服务器访问
- 不在以上两者中的域名：如果其 IP 是 [中国大陆 IP](https://github.com/17mon/china_ip_list) 则直连，否则通过代理服务器访问 

## 获取与安装

### 直接下载二进制文件

See [the releases page](https://github.com/ARwMq9b6/dnsproxy/releases)

### 通过 docker 编译

```
$ docker build -t dnsproxy https://raw.githubusercontent.com/ARwMq9b6/dnsproxy/master/cmd/dnsproxy/Dockerfile
$ docker run -v $PWD/target:/target dnsproxy
```

### 本地编译

```
$ go get -d -u github.com/ARwMq9b6/dnsproxy
$ cd $GOPATH/src/github.com/ARwMq9b6/dnsproxy/cmd/dnsproxy
$ make
```

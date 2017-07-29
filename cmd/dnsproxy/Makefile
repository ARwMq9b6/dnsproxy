ifeq ($(TARGETOS), )
    TARGETOS = $(shell go env GOOS)
endif

ifeq ($(TARGETARCH), )
    TARGETARCH = $(shell go env GOARCH)
endif

EXEXT :=
ifeq ($(TARGETOS), windows)
    EXEXT = .exe
endif

all: executable generate

executable: target/dnsproxy$(EXEXT)

target/dnsproxy$(EXEXT): main.go config.go $(shell find ../.. -maxdepth 1 -type f -name '*.go') ../../.vendor
	env GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -o target/dnsproxy$(EXEXT)

../../.vendor: ../../Gopkg.toml ../../Gopkg.lock
	cd ../..;\
	dep ensure -v
	touch ../../.vendor

generate: .generate

.generate: generator.go china_ip_list/china_ip_list.txt dnsmasq-china-list/accelerated-domains.china.conf gfwlist/gfwlist.txt
	go generate
	touch .generate

.PHONY: all executable generate

FROM golang:latest
# install requirement: dep
RUN go get -u github.com/golang/dep/cmd/dep

RUN go get -u github.com/ARwMq9b6/dnsproxy

WORKDIR $GOPATH/src/github.com/ARwMq9b6/dnsproxy/cmd/dnsproxy
ENV TARGETOS=$GOOS TARGETARCH=$GOARCH
VOLUME /target

CMD make && cp target/* /target

FROM golang:1.7.3
WORKDIR /go/src/github.com/octarinesec/kube-recon
RUN apt update && apt install -y libpcap-dev
COPY main.go .
RUN go get -v
RUN go build --ldflags '-extldflags "-static"' main.go

FROM alpine
RUN apk --no-cache add ca-certificates curl
WORKDIR /root/
COPY --from=0 /go/src/github.com/octarinesec/kube-recon/main /kube-recon
# CMD ["./kube-recon"]  

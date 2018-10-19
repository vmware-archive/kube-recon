FROM golang:1.7.3
WORKDIR /go/src/github.com/octarinesec/kube-recon
RUN apt update && apt install -y libpcap-dev
COPY main.go .
RUN go get -v
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' main.go

FROM alpine
RUN apk --no-cache add ca-certificates curl nmap libpcap-dev nmap-scripts bash
WORKDIR /
RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.11.0/bin/linux/amd64/kubectl && chmod +x kubectl
COPY --from=0 /go/src/github.com/octarinesec/kube-recon/main /kube-recon
COPY http-swagger.nse .
ENTRYPOINT ["/bin/sh"]

# Reconnaissance Test for Kubernetes

The purpose of this tool is to gather maximum information from a pod inside kubernetes cluster.

The output report shows pods/services that are visible and accessible to help better understand where security is
not tight enough

## Development

### Requiremnts:
* Go version > 1.10

### Running
```bash
go get
go run main.go
```
### Building
```bash
go build
sudo ./kube_recon
```

## Example

```bash
wget https://github.com/octarinesec/research/releases/download/kube-recon-v0.1/kube_recon
chmod a+x kube_recon
# for help run ./kube_recon --help
sudo ./kube_recon
```

Output:

```bash
2018/07/15 10:36:30 Running apt update
2018/07/15 10:36:43 Running apt install -y curl tcpdump nmap
2018/07/15 10:36:44 Running curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.11.0/bin/linux/amd64/kubectl
2018/07/15 10:37:25 Running chmod +x ./kubectl
2018/07/15 10:37:25 Running mv ./kubectl /usr/local/bin/kubectl
2018/07/15 10:37:25 Testing K8S API permissions
2018/07/15 10:37:29 Your K8S API Server permissions are wide open. Please consider using RBAC
2018/07/15 10:37:29 Accessible Pods:
2018/07/15 10:37:29 hello-minikube-1-7f76d5d58d-w7sdq
2018/07/15 10:37:29 Querying ARP Table for IPs:
2018/07/15 10:37:29 10.100.102.1
2018/07/15 10:37:29 Sniffing network to get IPs for 10 seconds
2018/07/15 10:37:29 Running tcpdump -i any -w capture.pcap -G 10 -W 1
2018/07/15 10:37:39 Found following IPS while sniffing:
2018/07/15 10:37:39 104.244.42.72
2018/07/15 10:37:39 172.217.18.14
2018/07/15 10:37:39 127.0.0.1
2018/07/15 10:37:39 192.30.253.125
2018/07/15 10:37:39 127.0.1.1
2018/07/15 10:37:39 10.100.102.1
2018/07/15 10:37:39 35.190.55.188
2018/07/15 10:37:39 216.58.214.110
2018/07/15 10:37:39 239.255.255.250
2018/07/15 10:37:39 35.190.66.65
2018/07/15 10:37:39 34.225.99.46
2018/07/15 10:37:39 35.193.211.56
2018/07/15 10:37:39 173.194.76.188
2018/07/15 10:37:39 192.30.253.113
2018/07/15 10:37:39 hello-minikube-1-7f76d5d58d-w7sdq
2018/07/15 10:37:39 52.216.227.224
2018/07/15 10:37:39 10.100.102.3
2018/07/15 10:37:39 Running Nmap on the discovered IPs
2018/07/15 10:37:39 Running nmap --host-timeout 10 -oX scan.xml 239.255.255.250
2018/07/15 10:37:40 Running nmap --host-timeout 10 -oX scan.xml 35.190.66.65
2018/07/15 10:37:50 Open ports for hostname: 35.190.66.65
2018/07/15 10:37:50 Running nmap --host-timeout 10 -oX scan.xml 34.225.99.46
```

## TODO
* Currently the tool assumes a pod running ubuntu. Create a more "cross-distribution" pacakge (get rid of apt-get commands in the tool).
* Improve Network Sniffer parsing. Add Protocol Detection & Parsing capabilities.
* Tests.

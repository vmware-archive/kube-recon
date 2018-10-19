# Reconnaissance Test for Kubernetes

The purpose of this tool is to gather maximum information from a pod inside kubernetes cluster.

The output report shows pods/services that are visible and accessible to help better understand where security is
not tight enough

## Running

You can run the tool via already build docker which you deploy inside the cluster or install
the prerequisite and run the tool directly on an already running pod. The recommended way is to run the docker

## Kubernetes

```bash
kubectl run kuberecon1 --tty -i --image octarinesec/kube-recon:v11
./kube_recon # (This is inside the docker)
./kube_recon -help
./kube_recon -skip-nmap (full nmap might take alot of time)
```

Example Output:
```bash
2018/10/19 07:22:02 Testing K8S API permissions
2018/10/19 07:22:03 Your K8S API Server is configured properlly
2018/10/19 07:22:03 Trying to download EICAR file
2018/10/19 07:22:03 Downloaded EICAR successfully. No malware protection is in place
```

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

### Building Docker Image
```bash
docker build -t <Image Name> .
```

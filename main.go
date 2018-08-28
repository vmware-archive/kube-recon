package main

import (
	"flag"
	"io/ioutil"
	"log"
	"bytes"
	"os/exec"
	"strconv"
	"strings"
  "net/http"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"encoding/json"
	nmap "github.com/tomsteele/go-nmap"
)

func check_root() {
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()

	if err != nil {
		log.Fatal(err)
	}

	i, err := strconv.Atoi(string(output[:len(output)-1]))

	if err != nil {
		log.Fatal(err)
	}

	if i != 0 {
		log.Fatal("This program must be run as root! (sudo)")
	}
}

func exec_command_wrapper(name string, args ...string) string {
	log.Printf("Running %s %s", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	stdouterrr, err := cmd.CombinedOutput()
	if err != nil {
		print(string(stdouterrr))
		log.Fatal(err)
	}
	return string(stdouterrr)
}

type KubeRecon struct {
	ip_addresses map[string][]int
}

func newKubeRecon() *KubeRecon {
	ips := map[string][]int{}
	return &KubeRecon{ips}
}

func (k *KubeRecon) install_prerequisite() {
	exec_command_wrapper("apt", "update")
	exec_command_wrapper("apt", "install", "-y", "curl", "tcpdump", "nmap")
	exec_command_wrapper("curl", "-LO", "https://storage.googleapis.com/kubernetes-release/release/v1.11.0/bin/linux/amd64/kubectl")
	exec_command_wrapper("chmod", "+x", "./kubectl")
	exec_command_wrapper("mv", "./kubectl", "/usr/local/bin/kubectl")
}

func (k *KubeRecon) test_rbac() {
	log.Printf("Testing K8S API permissions")
	stdouterr, err := exec.Command("kubectl", "get", "pods").CombinedOutput()
	if err != nil {
		log.Print("Your K8S API Server is configured properlly")
	} else {
		log.Print("Your K8S API Server permissions are wide open. Please consider using RBAC")
		log.Print("Accessible Pods:")
		lines := strings.Split(string(stdouterr), "\n")
		for _, row := range lines[1 : len(lines)-1] {
			ip := strings.Split(row, " ")[0]
			log.Printf("%s", ip)
			k.ip_addresses[ip] = []int{}
		}
	}
}

func (k *KubeRecon) query_arp() {
	log.Printf("Querying ARP Table for IPs:")
	output, err := ioutil.ReadFile("/proc/net/arp")
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(output), "\n")
	for _, row := range lines[1 : len(lines)-1] {
		ip := strings.Split(row, " ")[0]
		log.Printf("%s", ip)
	}
}

func (k *KubeRecon) sniff_network(timeout int) {
	log.Printf("Sniffing network to get IPs for %d seconds", timeout)
	exec_command_wrapper("tcpdump", "-i", "any", "-w", "capture.pcap", "-G", strconv.Itoa(timeout), "-W", "1")
	handle, err := pcap.OpenOffline("capture.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			k.ip_addresses[ip.SrcIP.String()] = []int{}
			k.ip_addresses[ip.DstIP.String()] = []int{}
		}
	}
	log.Print("Found following IPS while sniffing:")
	for ip := range k.ip_addresses {
		log.Print(ip)
	}
}

func (k *KubeRecon) nmap() {
	log.Print("Running Nmap on the discovered IPs")
	for ip := range k.ip_addresses {
		exec_command_wrapper("nmap", "--host-timeout", "10", "-oX", "scan.xml", ip)
		output, err := ioutil.ReadFile("scan.xml")
		if err != nil {
			panic(err)
		}

		nmap_run, err := nmap.Parse(output)
		if err != nil {
			log.Fatal(err)
		}

		for _, host := range nmap_run.Hosts {
			log.Printf("Open ports for hostname: %s", host.Addresses[0].Addr)
			for _, port := range host.Ports {
				p := strconv.Itoa(port.PortId)
				log.Printf("%s", p)
			}
		}
	}
}

func (k *KubeRecon) swagger_search() {
	log.Print("Looking for swagger documentation files")
	for ip := range k.ip_addresses {
		var url = "http://" + ip + "/swagger.json"
		resp, err := http.Get(url)
		if err == nil {
			log.Printf("Found swagger documentation at %s:", url)
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			var out bytes.Buffer
			json.Indent(&out, body, "", "    ")
			log.Print(out.String())
		}
	}
}

func (k *KubeRecon) run() {

	skip_prerequisite := flag.Bool("skip-prerequisite", false, "Skip installing prerequisite on the system")
	skip_rbac := flag.Bool("skip-rbac", false, "Skip RBAC test")
	skip_arp := flag.Bool("skip-arp", false, "Skip ARP query")
	skip_sniffer := flag.Bool("skip-sniffer", false, "Skip network sniffer")
	skip_nmap := flag.Bool("skip-nmap", false, "Skip NMAP scab")
	skip_swagger := flag.Bool("skip-swagger", false, "Skip Swagger search")
	sniffer_timeout := flag.Int("sniffer-timeout", 10, "Number of seconds to sniff network")

	flag.Parse()

	check_root()

	if !*skip_prerequisite {
		k.install_prerequisite()
	}
	if !*skip_rbac {
		k.test_rbac()
	}
	if !*skip_arp {
		k.query_arp()
	}
	if !*skip_sniffer {
		k.sniff_network(*sniffer_timeout)
	}

	if !*skip_nmap {
		k.nmap()
	}

	if !*skip_swagger {
		k.swagger_search()
	}

}

func main() {

	k := newKubeRecon()
	k.run()

}

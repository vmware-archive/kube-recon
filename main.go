package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
)

const torExitNode string = "103.1.206.100"

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
	ip_addresses map[string]bool
}

func newKubeRecon() *KubeRecon {
	ips := map[string]bool{}
	return &KubeRecon{ips}
}

func (k* KubeRecon) get_ip_addr() {
	log.Printf("Getting local ip address and subnet")
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	// handle err
	for _, i := range ifaces {
	    addrs, err := i.Addrs()
		if err != nil {
			log.Fatal(err)
		}
	    if (i.Flags & net.FlagLoopback) == net.FlagLoopback {
	    	continue
		}
	    // handle err
	    for _, addr := range addrs {
	        var ip net.IP
	        switch v := addr.(type) {
	        case *net.IPNet:
	                ip = v.IP
	        case *net.IPAddr:
	                ip = v.IP
	        }
	        if ip.To4() != nil && !(strings.HasPrefix(ip.String(), "172")) {
				k.ip_addresses[ip.String() + "/24"] = true
			}
	        // process IP address
	    }
	}
}

func (k *KubeRecon) test_rbac() {
	log.Printf("Testing K8S API permissions")
	// exec_command_wrapper("mv", "./kubectl", "/usr/local/bin/kubectl")
	stdouterr, err := exec.Command("./kubectl", "get", "pods").CombinedOutput()
	if err != nil {
		log.Print("Your K8S API Server is configured properlly")
	} else {
		log.Print("Your K8S API Server permissions are wide open. Please consider using RBAC")
		log.Print("Accessible Pods:")
		lines := strings.Split(string(stdouterr), "\n")
		for _, row := range lines[1 : len(lines)-1] {
			ip := strings.Split(row, " ")[0]
			log.Printf("%s", ip)
			k.ip_addresses[ip] = true
		}
	}
}

func (k *KubeRecon) nmap() {
	log.Print("Running Nmap on the discovered IPs")
	k.get_ip_addr()
	for ip := range k.ip_addresses {
		output := exec_command_wrapper("nmap",
									  "-p", "[1-65535]",
										   "--script", "http-swagger.nse",
										   "--script", "cassandra-brute",
										   "--script", "http-brute",
										   "--script", "http-proxy-brute",
										   "--script", "ms-sql-brute",
										   "--script", "mysql-brute",
										   "--script", "pgsql-brute",
										   "--script", "mongodb-brute",
										   ip)
		log.Printf(output)
	}
}

func (k * KubeRecon) test_tor_exit_nodes() {
	log.Print("Testing connection to Tor exit node")
	resp, err := http.Get("http://" + torExitNode)
	if err != nil {
		log.Fatalln(err)
	}
	if resp.StatusCode == 200 {
		log.Print("Established connection to Tor Node Successfully")
	} else {
		log.Print("Connection to Tor Node was blocked")
	}
}

func (k *KubeRecon) run() {

	skip_rbac := flag.Bool("skip-rbac", false, "Skip RBAC test")
	skip_nmap := flag.Bool("skip-nmap", false, "Skip NMAP scan")
	skip_tor := flag.Bool("skip-tor", false, "Skip TOR test")

	flag.Parse()
	// check_root()

	if !*skip_rbac {
		k.test_rbac()
	}

	if !*skip_nmap {
		k.nmap()
	}

	if !*skip_tor {
		k.test_tor_exit_nodes()
	}

}

func main() {

	k := newKubeRecon()
	k.run()

}

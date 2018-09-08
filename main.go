package main

import (
	"flag"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
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
	exec_command_wrapper("curl", "-LO", "https://storage.googleapis.com/kubernetes-release/release/v1.11.0/bin/linux/amd64/kubectl")
	exec_command_wrapper("chmod", "+x", "./kubectl")
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

func (k *KubeRecon) run() {

	skip_rbac := flag.Bool("skip-rbac", false, "Skip RBAC test")
	skip_nmap := flag.Bool("skip-nmap", false, "Skip NMAP scan")

	flag.Parse()
	// check_root()

	if !*skip_rbac {
		k.test_rbac()
	}

	if !*skip_nmap {
		k.nmap()
	}

}

func main() {

	k := newKubeRecon()
	k.run()

}

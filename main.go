package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"golang.org/x/crypto/ssh"
)

type mcaDump struct {
	Version  string `json:"version"`
	VAPTable []struct {
		Name     string `json:"name"`
		STATable []struct {
			IP     string `json:"ip"`
			MAC    string `json:"mac"`
			Signal int    `json:"signal"`
		} `json:"sta_table"`
	} `json:"vap_table"`
}

var wifiStationSignalDBM = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "wifi_station_signal_dbm",
	Help: "The current WiFi signal strength, in decibel-milliwatts (dBm).",
}, []string{"ifname", "mac"})

var unifiOSInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "unifi_os_info",
	Help: "Information on the Unifi OS running on the target.",
}, []string{"version"})

type unifiCollector struct {
	TargetIP          string
	TargetFingerprint string
	Password          string

	client *ssh.Client
}

func (u *unifiCollector) Collect(metrics chan<- prometheus.Metric) {
	log.Println("collecting metrics")

	if u.client == nil {
		log.Println("establishing new connection to target")

		config := &ssh.ClientConfig{
			User: "admin",
			Auth: []ssh.AuthMethod{
				ssh.Password(u.Password),
			},
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				fingerprint := ssh.FingerprintLegacyMD5(key)
				// XXX we don't need to do a constant-time comparison, right? And comparing the fingerprint
				//     should suffice, yeah?
				if fingerprint != u.TargetFingerprint {
					return errors.New("fingerprint mismatch")
				}
				return nil
			},
		}

		client, err := ssh.Dial("tcp", u.TargetIP+":22", config)
		if err != nil {
			log.Printf("got error of type %[1]T when establishing SSH connection: %[1]v", err)
			metrics <- prometheus.NewInvalidMetric(prometheus.NewInvalidDesc(err), err)
			return
		}
		u.client = client
	}

	session, err := u.client.NewSession()
	if err != nil {
		log.Printf("got error of type %[1]T when creating a session: %[1]v", err)
		metrics <- prometheus.NewInvalidMetric(prometheus.NewInvalidDesc(err), err)
		err := u.client.Close()
		if err != nil {
			log.Printf("got error of type %[1]T when closing SSH connection during cleanup: %[1]v", err)
		}
		u.client = nil
		return
	}
	defer session.Close()

	b := &bytes.Buffer{}
	session.Stdout = b

	if err := session.Run("mca-dump"); err != nil {
		log.Printf("got error of type %[1]T when running remote command: %[1]v", err)
		metrics <- prometheus.NewInvalidMetric(prometheus.NewInvalidDesc(err), err)

		return
	}

	dump := mcaDump{}
	err = json.Unmarshal(b.Bytes(), &dump)
	if err != nil {
		log.Printf("got error of type %[1]T when deserializing remote command output: %[1]v", err)
		metrics <- prometheus.NewInvalidMetric(prometheus.NewInvalidDesc(err), err)

		return
	}

	{
		m := unifiOSInfo.WithLabelValues(dump.Version)
		m.Set(1)
		metrics <- m
	}

	for _, vapTable := range dump.VAPTable {
		for _, staTable := range vapTable.STATable {
			m := wifiStationSignalDBM.WithLabelValues(vapTable.Name, staTable.MAC)
			m.Set(float64(staTable.Signal))
			metrics <- m
		}
	}
}

func (u *unifiCollector) Describe(metrics chan<- *prometheus.Desc) {
	log.Println("describing metrics")

	wifiStationSignalDBM.WithLabelValues("", "").Describe(metrics)
	unifiOSInfo.WithLabelValues("").Describe(metrics)
}

func main() {
	targetIP := os.Args[1]
	targetFingerprint := os.Args[2]
	password := os.Getenv("SSH_PASS")

	c := &unifiCollector{
		TargetIP:          targetIP,
		TargetFingerprint: targetFingerprint,
		Password:          password,
	}

	prometheus.DefaultRegisterer.MustRegister(c)

	addr := "0.0.0.0:9001"

	log.Printf("listening on %v", addr)
	err := http.ListenAndServe(addr, promhttp.Handler())
	if err != nil {
		log.Fatalf("error listening for connections: %v", err)
	}
}

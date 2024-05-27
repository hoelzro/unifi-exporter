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

type unifiCollector struct {
	TargetIP          string
	TargetFingerprint string
	Password          string
}

func (u *unifiCollector) Collect(metrics chan<- prometheus.Metric) {
	log.Println("collecting metrics")

	// XXX lazily connect to target via SSH
	// XXX refresh connection/session if it's lapsed
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
		panic(err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		panic(err)
	}
	defer session.Close()

	b := &bytes.Buffer{}
	session.Stdout = b

	if err := session.Run("mca-dump"); err != nil {
		panic(err)
	}

	dump := mcaDump{}
	err = json.Unmarshal(b.Bytes(), &dump)
	if err != nil {
		panic(err)
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

	log.Println("listening on 127.0.0.1:9001")
	err := http.ListenAndServe("127.0.0.1:9001", promhttp.Handler())
	if err != nil {
		panic(err)
	}
}

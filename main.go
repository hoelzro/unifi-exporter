package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

var probeSuccessMetric = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "probe_success",
	Help: "Whether or not we were able to successfully probe the target.",
})

type unifiCollector struct {
	TargetIP          string
	TargetFingerprint string
	Password          string

	client *ssh.Client
}

func (u *unifiCollector) getDump() (*mcaDump, error) {
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
			return nil, fmt.Errorf("establishing SSH connection: %w", err)
		}
		u.client = client
	}

	session, err := u.client.NewSession()
	if err != nil {
		closeErr := u.client.Close()
		u.client = nil
		return nil, fmt.Errorf("creating a session: %w", errors.Join(
			err,
			closeErr,
		))
	}
	defer session.Close()

	b := &bytes.Buffer{}
	session.Stdout = b

	if err := session.Run("mca-dump"); err != nil {
		return nil, fmt.Errorf("running remote command: %w", err)
	}

	dump := mcaDump{}
	err = json.Unmarshal(b.Bytes(), &dump)
	if err != nil {
		return nil, fmt.Errorf("deserializing remote command output: %w", err)
	}

	return &dump, nil
}

func (u *unifiCollector) Collect(metrics chan<- prometheus.Metric) {
	log.Println("collecting metrics")

	dump, err := u.getDump()
	if err != nil {
		log.Printf("got error of type %[1]T: %[1]v", err)
		probeSuccessMetric.Set(0)
		metrics <- probeSuccessMetric
		return
	}

	probeSuccessMetric.Set(1)
	metrics <- probeSuccessMetric

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
	probeSuccessMetric.Describe(metrics)
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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"golang.org/x/crypto/ssh"
)

const (
	dumpTimeout  = 5 * time.Second
	panicTimeout = time.Minute
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
	lock   sync.Mutex
}

func (u *unifiCollector) getDump(ctx context.Context) (*mcaDump, error) {
	u.lock.Lock()
	defer u.lock.Unlock()

	// x/crypto/ssh doesn't really support the use of contexts (and my experiments with
	// the Timeout client option don't seem to do anything), so we'll use a "watcher" goroutine
	// that closes the connection upon context close to try to signal the goroutine that's connecting
	// and establishing the session to exit, and panics after a much longer timeout in case that doesn't
	// work.  We need…

	// …a channel to signal the "watcher" goroutine that we're exiting
	finished := make(chan struct{})
	defer (func() {
		finished <- struct{}{}
		close(finished)
	})()

	// …a timer to tell the watcher to panic - since a crashed program would be better than one that's
	// indefinitely hung
	panicTimer := time.NewTimer(panicTimeout)
	defer panicTimer.Stop()

	// …a reference to the underlying connection for the "watcher" to close.
	//
	// I don't like that this is an io.Closer - I did that because it could be a net.Conn or an ssh.Conn,
	// which feels gross because the behavior could differ slightly, but this is more or less the best
	// we can do!
	var closer io.Closer
	if u.client != nil {
		closer = u.client.Conn
	}

	// …a reference to the context's "done" channel, which we need in a variable so we can set it to
	// nil when the context is done so we don't get repeated events from it
	doneChan := ctx.Done()

	go (func() {
		for {
			select {
			case <-doneChan:
				// our context is done, so try to effect a timeout
				doneChan = nil // set this to nil so that we don't run this case statement again
				if closer != nil {
					err := closer.Close()
					if err != nil {
						log.Printf("got error when closing connection upon timeout: %v", err)
					}
				}
			case <-finished:
				// everything is ok, so stop looping
				return
			case <-panicTimer.C:
				// too much time has passed - we're probably going to hang forever, so crash
				panic("unable to return error upon timeout - failing hard")
			}
		}
	})()

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

		var dialer net.Dialer

		var err error
		connection, err := dialer.DialContext(ctx, "tcp", u.TargetIP+":22")
		if err != nil {
			return nil, fmt.Errorf("establishing SSH connection (dial): %w", err)
		}
		closer = connection

		conn, chans, reqs, err := ssh.NewClientConn(connection, u.TargetIP+":22", config)
		if err != nil {
			return nil, fmt.Errorf("establishing SSH connection (new client conn): %w", err)
		}

		client := ssh.NewClient(conn, chans, reqs)
		u.client = client
		closer = client.Conn
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
	ctx, cancel := context.WithTimeout(context.TODO(), dumpTimeout)
	defer cancel()

	log.Println("collecting metrics")

	dump, err := u.getDump(ctx)
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

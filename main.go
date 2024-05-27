package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	targetIP := os.Args[1]
	targetFingerprint := os.Args[2]
	password := os.Getenv("SSH_PASS")

	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fingerprint := ssh.FingerprintLegacyMD5(key)
			// XXX we don't need to do a constant-time comparison, right? And comparing the fingerprint
			//     should suffice, yeah?
			if fingerprint != targetFingerprint {
				return errors.New("fingerprint mismatch")
			}
			return nil
		},
	}

	client, err := ssh.Dial("tcp", targetIP+":22", config)
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
	fmt.Println(b.String())
}

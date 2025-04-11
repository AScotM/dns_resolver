package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func resolveDNS(domain string) {
	server := "8.8.8.8:53" // Google's Public DNS

	// Build a DNS request message
	msg := make([]byte, 512)
	msg[0] = 0x12 // ID
	msg[1] = 0x34
	msg[2] = 1 // Standard query
	msg[5] = 1 // One question

	offset := 12
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		msg[offset] = byte(len(label)) // Correctly get the string length
		offset++
		copy(msg[offset:], label) // Copy the label bytes into the message
		offset += len(label)
	}
	msg[offset] = 0 // End of domain name
	msg[offset+1] = 0 // Type A
	msg[offset+2] = 1 // IN

	// Send query via UDP
	conn, err := net.Dial("udp", server)
	if err != nil {
		fmt.Println("Error connecting to DNS server:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(msg[:offset+3]) // Send the correct message length
	if err != nil {
		fmt.Println("Error sending query:", err)
		return
	}

	// Read response
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	fmt.Println("Received DNS Response:", resp[:n])
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <domain>")
		return
	}

	domain := os.Args[1]
	resolveDNS(domain)
}


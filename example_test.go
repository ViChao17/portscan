package portscan_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ViChao17/portscan"
)

// ExampleScanner_Scan checks a single port of the local machine.
func ExampleScanner_Scan() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	scanner, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}

	results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, portscan.Ports(port))
	if err != nil {
		log.Fatal(err)
	}

	for result := range results {
		fmt.Printf("%s %s\n", result.Host, result.State)
	}

	// Output:
	// 127.0.0.1 open
}

// ExampleParsePorts shows how to build a port set from a textual
// specification.
func ExampleParsePorts() {
	set, err := portscan.ParsePorts("22, 80, 443, 1000-1002")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(set)
	fmt.Println(set.Len())

	// Output:
	// 22,80,443,1000-1002
	// 6
}

// ExamplePortSet_Union combines ranges and individual ports.
func ExamplePortSet_Union() {
	set := portscan.Range(1, 3).Union(portscan.Ports(80, 443))
	fmt.Println(set)

	// Output:
	// 1-3,80,443
}

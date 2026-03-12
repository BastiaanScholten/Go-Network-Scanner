package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	// Setting up all the different flags
	target := flag.String("target", "", "The target IP address, Domain, or CIDR block (e.g., \"192.168.1.1\", \"example.com\", or \"10.0.0.0/24\")")
	port := flag.String("port", "", "The port or port range to scan (e.g., 80, 443, or \"1-65535\")")
	workers := flag.Int("workers", 50, "Number of concurrent workers")
	timeout := flag.Duration("timeout", 100*time.Millisecond, "Max time to wait for a response per port (e.g., '500ms' or '1s')")
	verbose := flag.Bool("v", false, "Enable verbose mode to see every connection attempt (e.g., true or false)")
	outputFile := flag.String("o", "", "Save the results to a file (e.g., 'results.txt' or 'output.cvs')")

	// Parsing all flags
	flag.Parse()

	// Checking if flags aren't empty
	if *target == "" {
		fmt.Println("Error: The -target flag is required.")
		flag.Usage()
		os.Exit(1)
	} else if *port == "" {
		fmt.Println("Error: The -port flag is required.")
		flag.Usage()
		os.Exit(1)
	}

	//Create Channels
	tasks := make(chan ScanTask, *workers)
	var allResults []ScanResult
	collectorDone := make(chan bool)
	results := make(chan ScanResult)

	// Splitting port string(s) to unsigned integers for startPort and endPort
	var startPort, endPort int
	var err error
	portParts := strings.Split(*port, "-")

	startPort, err = strconv.Atoi(portParts[0])
	if err != nil {
		fmt.Printf("An error has occurred: %s\n", err)
		return
	}

	if len(portParts) == 2 {
		endPort, err = strconv.Atoi(portParts[1])
		if err != nil {
			fmt.Printf("An error has occurred: %s\n", err)
			return
		}
	} else {
		endPort = startPort
	}

	// Print input
	fmt.Println("Set target to:", *target)
	fmt.Printf("Set port range: %d through %d\n", startPort, endPort)
	fmt.Println("Set workers amount to:", *workers)
	fmt.Println("Set timeout to:", *timeout)
	fmt.Println("Set verbose to:", *verbose)
	if *outputFile != "" {
		fmt.Println("Set output file to:", *outputFile)
	}

	// DNS Resolving if it isn't an IP
	foundIPs, err := net.LookupIP(*target)
	if err == nil && len(foundIPs) > 0 {
		// We pakken het eerste IPv4 adres dat we vinden
		for _, fIP := range foundIPs {
			if fIP.To4() != nil {
				*target = fIP.String()
				break
			}
		}
	}

	// Parse IP
	var startIP []byte
	var cidr *net.IPNet
	ip := net.ParseIP(*target)
	if ip == nil {
		_, cidr, err = net.ParseCIDR(*target)
		if err != nil {
			fmt.Printf("An error has occurred: %s\n", err)
			return
		}

		pureIP := cidr.IP.To4()
		if pureIP == nil {
			fmt.Printf("An error has occurred: %s\n", err)
		}
		startIP = pureIP.To4()

		fmt.Println("ip:", cidr.String())
		*target = cidr.String()
		amount, _ := cidr.Mask.Size() // Retrieves the CIDR notation
		fmt.Println("CIDR Notation:", amount)
		fmt.Println("Amount of addresses:", 1<<(32-amount)) // Bitwise left-shift operator
		fmt.Println("Current ip", pureIP[0])
		fmt.Println("mask bits", net.CIDRMask(amount, 32))
	} else {
		fmt.Println("ip:", ip)
		ip = ip.To4()
	}

	// Ensure we have a valid 4-byte IPv4 address
	currentIP := make(net.IP, len(startIP))
	copy(currentIP, startIP)

	// Setup collector channel
	go func() {
		for res := range results {
			allResults = append(allResults, res)
		}
		collectorDone <- true
	}()

	// Initiate a wait group
	var wg sync.WaitGroup

	// Create a pool of workers to scan ports concurrently
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {

				address := net.JoinHostPort(task.IP, fmt.Sprintf("%d", task.Port))

				// Sending request
				conn, err := net.DialTimeout("tcp", address, *timeout)
				if err != nil {
					if *verbose {
						fmt.Printf("[CLOSED] - %s\n", address)
					}
					continue
				}

				conn.Close()
				if *verbose {
					fmt.Printf("[OPEN] - %s\n", address)
				}
				res := ScanResult{
					IP:     task.IP,
					Port:   task.Port,
					IsOpen: true,
				}

				results <- res
			}
		}()
	}

	if cidr != nil {
		// Loop through the CIDR range and distribute tasks per IP
		for cidr.Contains(currentIP) {
			distributeTasks(currentIP, startPort, endPort, tasks)
			IncrementIP(currentIP)
		}
	} else {
		// Single IP target logic
		fmt.Println("ip:", ip)
		ip = ip.To4()
		startIP = ip
		distributeTasks(ip, startPort, endPort, tasks)
	}

	// Closing channel
	close(tasks)

	// Wait for all workers to finish
	wg.Wait()

	// Closing channel
	close(results)

	// Wait for the collector to finish archiving all results
	<-collectorDone

	fmt.Printf("\nFinished! %d open ports found.\n", len(allResults))

	if len(allResults) > 0 {
		fmt.Println("\n[Scan Results]")
		for _, res := range allResults {
			fmt.Printf("Status = OPEN | Address = %s:%d\n", res.IP, res.Port)
		}
	} else {
		fmt.Println("\nNo open ports were found on the target(s).")
	}

	if *outputFile != "" {
		err := saveToFile(*outputFile, allResults)
		if err != nil {
			fmt.Printf("Error saving to file: %s\n", err)
		} else {
			fmt.Printf("Results successfully saved to %s\n", *outputFile)
		}
	}
}

// IncrementIP moves the IP address to the next one in line
func IncrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {

		ip[i]++
		if ip[i] != 0 {
			return
		}
	}

}

// Create scan tasks for every port in the range and send to channel
func distributeTasks(ip net.IP, start int, end int, tasks chan ScanTask) {
	for p := start; p <= end; p++ {
		tasks <- ScanTask{
			IP:   ip.To4().String(),
			Port: uint16(p),
		}
	}
}

// Save found open ports to a local file
func saveToFile(filename string, results []ScanResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, res := range results {
		line := fmt.Sprintf("IP: %s | Port: %d | Status: Open\n", res.IP, res.Port)
		file.WriteString(line)
	}
	return nil
}

type ScanTask struct {
	IP   string
	Port uint16 // Usage of uint16 since TCP ports are 16-bit unsigned integers (0-65535)
}

type ScanResult struct {
	IP     string
	Port   uint16
	IsOpen bool
}

package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

const VERSION = "2.0"

type ScanResult struct {
	Target string
	IP     string
	Port   int
	Status string
	Banner string
}

var (
	vulnerableVersions = []string{
		"SSH-2.0-OpenSSH_1", "SSH-2.0-OpenSSH_2", "SSH-2.0-OpenSSH_3",
		"SSH-2.0-OpenSSH_4.0", "SSH-2.0-OpenSSH_4.1", "SSH-2.0-OpenSSH_4.2",
		"SSH-2.0-OpenSSH_4.3", "SSH-2.0-OpenSSH_4.4", "SSH-2.0-OpenSSH_8.5",
		"SSH-2.0-OpenSSH_8.6", "SSH-2.0-OpenSSH_8.7", "SSH-2.0-OpenSSH_8.8",
		"SSH-2.0-OpenSSH_8.9", "SSH-2.0-OpenSSH_9.0", "SSH-2.0-OpenSSH_9.1",
		"SSH-2.0-OpenSSH_9.2", "SSH-2.0-OpenSSH_9.3", "SSH-2.0-OpenSSH_9.4",
		"SSH-2.0-OpenSSH_9.5", "SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_9.7",
	}
	excludedVersions = []string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		"SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu3.6",
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3",
		"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6",
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
		"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
	}
)

func displayBanner() {
	banner := `
   _____ ____  _   _ _____ _____ _   _ ______ _       _____ _____ _    _ 
  / ____/ __ \| \ | |_   _|_   _| \ | |  ____| |     / ____/ ____| |  | |
 | (___| |  | |  \| | | |   | | |  \| | |__  | |    | (___| (___ | |__| |
  \___ \| |  | | . ' | | |   | | | . ' |  __| | |     \___ \\___ \|  __  |
  ____) | |__| | |\  |_| |_ _| |_| |\  | |____| |____ ____) |___) | |  | |
 |_____/ \____/|_| \_|_____|_____|_| \_|______|______|_____/_____/|_|  |_|
                                                                          
 Advanced CVE-2024-6387 Vulnerability Scanner - v%s
`
	color.Cyan(banner, VERSION)
}

func scanHost(target string, port int, timeout time.Duration) ScanResult {
	result := ScanResult{Target: target, Port: port, Status: "closed"}

	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		result.Status = "resolution_failed"
		return result
	}

	ip := ips[0].String()
	result.IP = ip

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	banner, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		result.Status = "error"
		result.Banner = err.Error()
		return result
	}

	result.Banner = strings.TrimSpace(banner)
	result.Status = analyzeVersion(result.Banner)
	return result
}

func analyzeVersion(banner string) string {
	if !strings.HasPrefix(banner, "SSH-2.0-") {
		return "unknown"
	}
	for _, v := range vulnerableVersions {
		if strings.HasPrefix(banner, v) {
			for _, e := range excludedVersions {
				if banner == e {
					return "patched"
				}
			}
			return "vulnerable"
		}
	}
	return "secure"
}

func processTargets(targets []string, port int, timeout time.Duration, concurrency int) []ScanResult {
	results := make([]ScanResult, 0, len(targets))
	jobs := make(chan string, len(targets))
	resultChan := make(chan ScanResult, len(targets))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				resultChan <- scanHost(target, port, timeout)
			}
		}()
	}

	go func() {
		for _, target := range targets {
			jobs <- target
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	bar := progressbar.Default(int64(len(targets)))
	for result := range resultChan {
		results = append(results, result)
		bar.Add(1)
	}

	return results
}

func printResults(results []ScanResult) {
	var vulnerable, secure, patched, unknown, closed, resolutionFailed int

	for _, r := range results {
		switch r.Status {
		case "vulnerable":
			vulnerable++
		case "secure":
			secure++
		case "patched":
			patched++
		case "unknown":
			unknown++
		case "closed":
			closed++
		case "resolution_failed":
			resolutionFailed++
		}
	}

	fmt.Println("\nScan Results:")
	color.Red("🚨 Vulnerable: %d", vulnerable)
	color.Green("🛡️ Secure: %d", secure)
	color.Yellow("🔧 Patched: %d", patched)
	color.Cyan("❓ Unknown: %d", unknown)
	color.Blue("🔒 Closed: %d", closed)
	color.Magenta("🔍 Resolution Failed: %d", resolutionFailed)

	fmt.Println("\nDetailed Results:")
	for _, r := range results {
		switch r.Status {
		case "vulnerable":
			color.Red("❌ %s (%s): Vulnerable - %s", r.Target, r.IP, r.Banner)
		case "secure":
			color.Green("✅ %s (%s): Secure - %s", r.Target, r.IP, r.Banner)
		case "patched":
			color.Yellow("🔒 %s (%s): Patched - %s", r.Target, r.IP, r.Banner)
		case "unknown":
			color.Cyan("❓ %s (%s): Unknown - %s", r.Target, r.IP, r.Banner)
		case "closed":
			color.Blue("🚫 %s (%s): Port Closed", r.Target, r.IP)
		case "resolution_failed":
			color.Magenta("🔍 %s: DNS Resolution Failed", r.Target)
		}
	}
}

func saveToCSV(results []ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	err = writer.Write([]string{"Target", "IP", "Port", "Status", "Banner"})
	if err != nil {
		return err
	}

	for _, result := range results {
		err := writer.Write([]string{
			result.Target,
			result.IP,
			fmt.Sprintf("%d", result.Port),
			result.Status,
			result.Banner,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	var port int
	var timeout float64
	var concurrency int
	var outputFile string
	var targetFile string

	rootCmd := &cobra.Command{
		Use:   "sentinelssh [flags] [targets...]",
		Short: "Advanced CVE-2024-6387 Vulnerability Scanner",
		Long: `SentinelSSH is an advanced tool for scanning SSH servers to detect the CVE-2024-6387 vulnerability.

It supports scanning individual IP addresses, domain names, and can read targets from a file.
The tool provides detailed output and can save results to a CSV file for further analysis.

Usage:
  sentinelssh [flags] [targets...]

Examples:
  sentinelssh 192.168.1.1
  sentinelssh example.com
  sentinelssh -p 2222 192.168.1.1 example.com
  sentinelssh -f targets.txt
  sentinelssh -o results.csv 192.168.1.0/24`,
		Run: func(cmd *cobra.Command, args []string) {
			displayBanner()

			var targets []string
			if targetFile != "" {
				file, err := os.Open(targetFile)
				if err != nil {
					color.Red("Error opening target file: %v", err)
					os.Exit(1)
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					targets = append(targets, strings.TrimSpace(scanner.Text()))
				}
			}
			targets = append(targets, args...)

			if len(targets) == 0 {
				color.Red("Error: No targets specified. Use --help for usage information.")
				os.Exit(1)
			}

			results := processTargets(targets, port, time.Duration(timeout*float64(time.Second)), concurrency)

			printResults(results)

			if outputFile != "" {
				err := saveToCSV(results, outputFile)
				if err != nil {
					color.Red("Error saving results to CSV: %v", err)
				} else {
					color.Green("Results saved to %s", outputFile)
				}
			}
		},
	}

	rootCmd.Flags().IntVarP(&port, "port", "p", 22, "Port number to scan")
	rootCmd.Flags().Float64VarP(&timeout, "timeout", "t", 5.0, "Connection timeout in seconds")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 100, "Number of concurrent scans")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for detailed results (CSV format)")
	rootCmd.Flags().StringVarP(&targetFile, "file", "f", "", "File containing list of targets")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

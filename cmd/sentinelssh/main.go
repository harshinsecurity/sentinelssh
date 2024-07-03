package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/harshinsecurity/sentinelssh/internal/scanner"
	"github.com/harshinsecurity/sentinelssh/internal/utils"
	"github.com/harshinsecurity/sentinelssh/pkg/models"
)

const VERSION = "3.0"

func displayBanner() {
	banner := `
   _____ ______ _   _ _______ _____ _   _ ______ _      _____ _____ _    _ 
  / ____|  ____| \ | |__   __|_   _| \ | |  ____| |    / ____/ ____| |  | |
 | (___ | |__  |  \| |  | |    | | |  \| | |__  | |   | (___| (___ | |__| |
  \___ \|  __| | . ' |  | |    | | | . ' |  __| | |    \___ \\___ \|  __  |
  ____) | |____| |\  |  | |   _| |_| |\  | |____| |____  __) |___) | |  | |
 |_____/|______|_| \_|  |_|  |_____|_| \_|______|______|_____/_____/|_|  |_|
                                                                            
 CVE-2024-6387 Vulnerability Scanner - v%s
`
	color.Cyan(banner, VERSION)
}

func processTargets(targets []string, port int, timeout time.Duration, concurrency int, silent bool) []models.ScanResult {
	results := make([]models.ScanResult, 0, len(targets))
	jobs := make(chan string, len(targets))
	resultChan := make(chan models.ScanResult, len(targets))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				resultChan <- scanner.ScanHost(target, port, timeout)
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

	var bar *progressbar.ProgressBar
	if !silent {
		bar = progressbar.NewOptions(len(targets),
			progressbar.OptionSetWidth(40),
			progressbar.OptionSetDescription("Scanning"),
			progressbar.OptionSetRenderBlankState(true),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[green]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}))
	}

	for result := range resultChan {
		results = append(results, result)

		if !silent {
			bar.Add(1)
		}

		if result.Status == "vulnerable" {
			if !silent {
				fmt.Println() // Print a newline before the vulnerable target
			}
			color.Red("❌ %s (%s): %s", result.Target, result.IP, result.Banner)
		}
	}

	if !silent {
		fmt.Println() // Print a newline after the progress bar
	}

	return results
}

func printResults(results []models.ScanResult) {
	vulnerableCount := 0
	for _, r := range results {
		if r.Status == "vulnerable" {
			vulnerableCount++
		}
	}
	fmt.Printf("\nTotal vulnerable targets found: %d\n", vulnerableCount)
}

func main() {
	var port int
	var timeout float64
	var concurrency int
	var targetFile string
	var silent bool

	rootCmd := &cobra.Command{
		Use:   "sentinelssh [flags] [targets...]",
		Short: "CVE-2024-6387 Vulnerability Scanner",
		Long: `SentinelSSH is a tool for scanning SSH servers to detect the CVE-2024-6387 vulnerability.

It supports scanning individual IP addresses, domain names, and can read targets from a file.

Usage:
  sentinelssh [flags] [targets...]

Examples:
  sentinelssh 192.168.1.1
  sentinelssh example.com
  sentinelssh -p 2222 192.168.1.1 example.com
  sentinelssh -f targets.txt
  sentinelssh -silent -f targets.txt`,
		Run: func(cmd *cobra.Command, args []string) {
			if !silent {
				displayBanner()
			}

			var targets []string
			if targetFile != "" {
				fileTargets, err := utils.ReadTargetsFromFile(targetFile)
				if err != nil {
					color.Red(err.Error())
					os.Exit(1)
				}
				targets = append(targets, fileTargets...)
				if !silent {
					color.Green("Loaded %d targets from file", len(fileTargets))
					fmt.Println() // Add a newline for better spacing
				}
			}
			targets = append(targets, args...)

			if len(targets) == 0 {
				color.Red("Error: No targets specified. Use --help for usage information.")
				os.Exit(1)
			}

			if !silent {
				fmt.Println("Starting scan...")
			}
			results := processTargets(targets, port, time.Duration(timeout*float64(time.Second)), concurrency, silent)

			if !silent {
				printResults(results)
			}
		},
	}

	rootCmd.Flags().IntVarP(&port, "port", "p", 22, "Port number to scan")
	rootCmd.Flags().Float64VarP(&timeout, "timeout", "t", 5.0, "Connection timeout in seconds")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 100, "Number of concurrent scans")
	rootCmd.Flags().StringVarP(&targetFile, "file", "f", "", "File containing list of targets")
	rootCmd.Flags().BoolVarP(&silent, "silent", "s", false, "Silent mode: only output vulnerable targets")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

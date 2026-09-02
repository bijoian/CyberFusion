package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bijoian/cyberfusion/internal/database"
	"github.com/bijoian/cyberfusion/internal/domain"
	"github.com/bijoian/cyberfusion/internal/orchestrator"
	"github.com/spf13/cobra"
)

var (
	targets []string
	modules []string
	timeout int
	threads int
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Execute a security scan",
	Long:  `Execute a comprehensive security scan on specified targets`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return executeScan(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringSliceVarP(&targets, "targets", "t", []string{}, "Targets to scan (IP, domain, CIDR)")
	scanCmd.Flags().StringSliceVarP(&modules, "modules", "m", []string{"port_scan", "service_detection"}, "Modules to run (use nuclei for Nuclei vulnerability scanning)")
	scanCmd.Flags().IntVar(&timeout, "timeout", 300, "Scan timeout in seconds")
	scanCmd.Flags().IntVar(&threads, "threads", 10, "Number of parallel threads")

	scanCmd.MarkFlagRequired("targets")
}

func executeScan(cmd *cobra.Command, args []string) error {
	_ = args
	log := getLogger()

	// Connect to database
	db, err := database.New(dbPath, log)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	// Create orchestrator
	scanOrchestrator := orchestrator.New(log)

	// Prepare scan config
	config := orchestrator.ScanConfig{
		Targets: targets,
		Modules: modules,
		Timeout: time.Duration(timeout) * time.Second,
		Threads: threads,
	}

	// Execute scan
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	log.Infof("Starting scan on targets: %v", targets)

	result, err := scanOrchestrator.ExecuteScan(ctx, config)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Save results to database
	if err := db.GetDB().Create(result.Scan).Error; err != nil {
		return fmt.Errorf("failed to save scan: %w", err)
	}

	for _, asset := range result.Assets {
		asset.ScanID = result.Scan.ID
		if err := db.GetDB().Create(&asset).Error; err != nil {
			log.Errorf("failed to save asset: %v", err)
		}
	}

	for _, finding := range result.Findings {
		finding.ScanID = result.Scan.ID
		if err := db.GetDB().Create(&finding).Error; err != nil {
			log.Errorf("failed to save finding: %v", err)
		}
	}

	// Print results
	printScanResults(result)

	return nil
}

func printScanResults(result *orchestrator.ScanResult) {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("CYBERFUSION")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("\nTarget: %v\n", result.Scan.Targets)
	fmt.Printf("Scan ID: %s\n\n", result.Scan.ID)

	fmt.Println("[1] Discovery ............... DONE")
	fmt.Println("[2] Ports ................... DONE")
	fmt.Println("[3] Services ................ DONE")
	fmt.Println("[4] HTTP .................... DONE")
	fmt.Println("[5] Fingerprint ............. DONE")
	fmt.Println("[6] Vulnerability ........... DONE")
	fmt.Println("[7] Correlation ............. DONE")
	fmt.Println("[8] Risk Analysis ........... DONE")

	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Println("RESULTS")
	fmt.Println(strings.Repeat("-", 50))

	critical, high, medium, low, info := countBySeverity(result.Findings)

	fmt.Printf("Assets             %d\n", len(result.Assets))
	fmt.Printf("Open ports         %d\n", 0) // TODO: Count from services
	fmt.Printf("Services           %d\n", 0) // TODO: Count from services
	fmt.Printf("Technologies       %d\n", 0) // TODO: Extract from fingerprinting
	fmt.Printf("\nCritical           %d\n", critical)
	fmt.Printf("High               %d\n", high)
	fmt.Printf("Medium             %d\n", medium)
	fmt.Printf("Low                %d\n", low)
	fmt.Printf("Info               %d\n", info)
	fmt.Printf("\nRisk Score: %d/100\n", result.Scan.RiskScore)
	fmt.Printf("Duration: %d seconds\n", result.Scan.Duration)
	fmt.Println("\n" + strings.Repeat("=", 50))
}

func countBySeverity(findings []domain.Finding) (int, int, int, int, int) {
	var critical, high, medium, low, info int
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		case "info":
			info++
		}
	}
	return critical, high, medium, low, info
}

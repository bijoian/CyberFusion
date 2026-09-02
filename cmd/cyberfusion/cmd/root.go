package cmd

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	logger *logrus.Logger
	dbPath string
	debug  bool
)

var rootCmd = &cobra.Command{
	Use:   "cyberfusion",
	Short: "CyberFusion - Unified Security Scanning & Intelligence Platform",
	Long:  `CyberFusion is a comprehensive security scanning platform that fuses multiple scanning engines.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	logger = logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	rootCmd.PersistentFlags().StringVar(&dbPath, "db-path", ".cyberfusion", "Path to database directory")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging")
}

func Execute() {
	if debug {
		logger.SetLevel(logrus.DebugLevel)
	}

	if err := rootCmd.Execute(); err != nil {
		logger.Fatal(err)
		os.Exit(1)
	}
}

func getLogger() *logrus.Logger {
	return logger
}

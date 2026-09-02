package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bijoian/cyberfusion/internal/api"
	"github.com/bijoian/cyberfusion/internal/authorization"
	"github.com/bijoian/cyberfusion/internal/database"
	"github.com/bijoian/cyberfusion/internal/orchestrator"
	"github.com/spf13/cobra"
)

var (
	apiListenAddress     string
	apiAuthorizedTargets []string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the Control REST API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runServer(cmd.Context())
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().StringVar(&apiListenAddress, "listen-address", "127.0.0.1:8080", "HTTP listen address")
	serverCmd.Flags().StringSliceVar(&apiAuthorizedTargets, "authorized-targets", nil, "Explicitly authorized targets or CIDR ranges")
	serverCmd.MarkFlagRequired("authorized-targets")
}

func runServer(ctx context.Context) error {
	log := getLogger()
	authorizer, err := authorization.NewTargetAuthorizer(apiAuthorizedTargets)
	if err != nil {
		return fmt.Errorf("invalid authorized targets: %w", err)
	}
	db, err := database.New(dbPath, log)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	handler, err := api.NewServer(api.Config{
		DB:           db.GetDB(),
		Orchestrator: orchestrator.New(log),
		Authorizer:   authorizer,
		Logger:       log,
	})
	if err != nil {
		return fmt.Errorf("failed to create API server: %w", err)
	}

	httpServer := &http.Server{
		Addr:              apiListenAddress,
		Handler:           handler.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serverContext, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Infof("Control API listening on %s", apiListenAddress)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("API server failed: %w", err)
		}
		return nil
	case <-serverContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("API server shutdown failed: %w", err)
		}
		if err := handler.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("scan worker shutdown failed: %w", err)
		}
		return nil
	}
}

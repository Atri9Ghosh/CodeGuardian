package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/codeguardian/codeguardian/internal/api"
	"github.com/codeguardian/codeguardian/internal/config"
	"github.com/codeguardian/codeguardian/internal/logger"
	"github.com/codeguardian/codeguardian/internal/metrics"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func main() {
	// Initialize configuration
	cfg, err := config.Load()
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	log := logger.New(cfg.LogLevel)
	log.Info("Starting CodeGuardian security scanner...")

	// Initialize metrics
	metrics.Init()

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// Initialize API handlers
	apiHandler := api.NewHandler(cfg, log)

	// Setup routes
	setupRoutes(router, apiHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Infof("Server starting on port %d", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Info("Server exited gracefully")
}

func setupRoutes(router *gin.Engine, handler *api.Handler) {
	// Health check
	router.GET("/health", handler.HealthCheck)

	// Metrics endpoint
	router.GET("/metrics", handler.Metrics)

	// API routes
	api := router.Group("/api/v1")
	{
		// GitHub webhook
		api.POST("/webhook/github", handler.GitHubWebhook)

		// Manual scan endpoint
		api.POST("/scan", handler.ManualScan)

		// Configuration endpoints
		api.GET("/config", handler.GetConfig)
		api.PUT("/config", handler.UpdateConfig)

		// Scan history
		api.GET("/scans", handler.GetScanHistory)
		api.GET("/scans/:id", handler.GetScanDetails)
	}
}

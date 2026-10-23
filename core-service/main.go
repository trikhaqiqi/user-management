package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"godigi/core-service/internal/config"
	"godigi/core-service/internal/handler"
	"godigi/core-service/internal/router"
	"godigi/core-service/internal/service"
	"godigi/pkg/database"
	"godigi/pkg/logger"
	"godigi/pkg/mailer"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "core-service:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := logger.New("core-service", cfg.LogLevel)
	gin.SetMode(gin.ReleaseMode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	mail := mailer.NewAsync(cfg.Mail, log, 2, 256)
	svc := service.New(pool, cfg.OTP, mail)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router.New(log, handler.New(svc), pool, cfg.InternalToken),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	mail.Close()
	return err
}

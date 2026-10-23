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

	"godigi/auth-service/internal/config"
	"godigi/auth-service/internal/handler"
	"godigi/auth-service/internal/router"
	"godigi/auth-service/internal/service"
	"godigi/pkg/database"
	"godigi/pkg/logger"
	"godigi/pkg/mailer"
	"godigi/pkg/ratelimit"
	"godigi/pkg/redisx"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "auth-service:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := logger.New("auth-service", cfg.LogLevel)
	gin.SetMode(gin.ReleaseMode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	rdb, err := redisx.Connect(ctx, cfg.RedisURL)
	if err != nil {
		return err
	}
	defer rdb.Close()

	mail := mailer.NewAsync(cfg.Mail, log, 2, 256)
	svc := service.New(pool, ratelimit.New(rdb, "auth"), mail, cfg, log)
	svc.StartJanitor(ctx, time.Hour)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router.New(log, handler.New(svc), pool, rdb, cfg.InternalToken),
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
	svc.Wait()
	mail.Close()
	return err
}

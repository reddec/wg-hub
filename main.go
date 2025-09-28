package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	"wg-hub/internal/api"
)

type Config struct {
	Bind        string
	AccessToken string
	Interface   string
	Ephemeral   bool
	TLSCert     string
	TLSKey      string
	TLSEnabled  bool
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	var config Config
	flag.StringVar(&config.Bind, "bind", getEnv("WG_HUB_HTTP_BIND", ":8080"), "Binding address [$WG_HUB_HTTP_BIND]")
	flag.StringVar(&config.AccessToken, "access-token", getEnv("WG_HUB_TTP_ACCESS_TOKEN", ""), "Protect HTTP request with the following content of Authorization header [$WG_HUB_TTP_ACCESS_TOKEN]")
	flag.StringVar(&config.Interface, "interface", getEnv("WG_HUB_INTERFACE", "wg0"), "interfaceName to use [$WG_HUB_INTERFACE]")
	flag.StringVar(&config.TLSKey, "tls-key", getEnv("WG_HUB_TLS_KEY", ""), "TLS private key [$WG_HUB_TLS_KEY]")
	flag.StringVar(&config.TLSCert, "tls-cert", getEnv("WG_HUB_TLS_CERT", ""), "TLS certificate [$WG_HUB_TLS_CERT]")
	flag.BoolVar(&config.TLSEnabled, "tls-enabled", getEnv("WG_HUB_TLS_ENABLED", "false") == "true", "Enable HTTPS [$WG_HUB_TLS_ENABLED]")
	flag.BoolVar(&config.Ephemeral, "ephemeral", getEnv("WG_HUB_EPHEMERAL", "false") == "true", "Do not save config on any change (eliminates dependency on wg-quick) [$WG_HUB_EPHEMERAL]")
	flag.Parse()

	if err := run(config); err != nil {
		slog.Error("failed to run", "error", err)
		os.Exit(1)
	}
}

func run(config Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	var handler = api.New(config.Interface, config.Ephemeral)
	if config.AccessToken != "" {
		slog.Info("access token provided")
		orig := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != config.AccessToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			orig.ServeHTTP(w, r)
		})
	}

	httpSrv := &http.Server{
		Addr:    config.Bind,
		Handler: handler,
	}

	// services

	go (func() {
		// server shutdown
		<-ctx.Done()
		_ = httpSrv.Close()
	})()

	slog.Info("ready", "tls", config.TLSEnabled, "bind", config.Bind)
	if config.TLSEnabled {
		return httpSrv.ListenAndServeTLS(config.TLSCert, config.TLSKey)
	}
	return httpSrv.ListenAndServe()
}

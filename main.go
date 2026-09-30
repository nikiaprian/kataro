package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"

	"keitaro/internal/config"
	"keitaro/internal/server"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	lookup, closeDB, err := openGeo(cfg.GeoIPDB)
	if err != nil {
		log.Fatal(err)
	}
	defer closeDB()

	srv := server.Server(cfg.Listen, server.New(cfg, *configPath, lookup))
	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on %s (%d routes)", cfg.Listen, len(cfg.Routes))
		errCh <- srv.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Fatal(err)
		}
	}
}

func openGeo(path string) (server.CountryLookup, func() error, error) {
	noop := func() error { return nil }
	if path == "" {
		return nil, noop, nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return geoLookup{db: db}, db.Close, nil
}

type geoLookup struct {
	db *geoip2.Reader
}

func (g geoLookup) Country(ip net.IP) (string, error) {
	rec, err := g.db.Country(ip)
	if err != nil {
		return "", err
	}
	return rec.Country.IsoCode, nil
}

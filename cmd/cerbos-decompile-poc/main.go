// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cerbos/cerbos/internal/workspace"
)

const (
	readHeaderTimeout = 5 * time.Second
	shutdownTimeout   = 5 * time.Second
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	policiesDir := flag.String("policies", "", "directory of policies to seed the workspace from")
	bundlePath := flag.String("bundle", "", "rule table bundle file to seed the workspace from")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ws, err := openWorkspace(ctx, *policiesDir, *bundlePath)
	if err != nil {
		return fmt.Errorf("failed to open workspace: %w", err)
	}
	defer ws.Close()

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           newServer(ws).routes(),
		ReadHeaderTimeout: readHeaderTimeout,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("cerbos-decompile-poc listening on %s", *addr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func openWorkspace(ctx context.Context, policiesDir, bundlePath string) (*workspace.Workspace, error) {
	switch {
	case bundlePath != "":
		f, err := os.Open(bundlePath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return workspace.FromBundle(ctx, f)
	case policiesDir != "":
		return workspace.FromDirectory(ctx, policiesDir)
	default:
		return workspace.New(ctx)
	}
}

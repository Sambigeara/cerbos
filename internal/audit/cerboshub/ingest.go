// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerboshub

import (
	"context"
	"time"
)

type ErrIngestBackoff struct {
	underlying error
	Backoff    time.Duration
}

func (e ErrIngestBackoff) Error() string {
	return e.underlying.Error()
}

type IngestSyncer interface {
	Sync(context.Context, [][]byte) error
}

// Impl implements the IngestSyncer interface.
type Impl struct{}

func NewIngestSyncer() *Impl {
	return &Impl{}
}

func (i *Impl) Sync(_ context.Context, _ [][]byte) error {
	return nil
}

// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/decompile"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/workspace"
)

//go:embed ui
var uiFS embed.FS

const maxYAMLDocBytes = 8 * 1024 * 1024

type server struct {
	ws *workspace.Workspace
}

func newServer(ws *workspace.Workspace) *server {
	return &server{ws: ws}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("POST /api/yaml", s.handleYAML)
	mux.HandleFunc("POST /api/policy/add", s.handlePolicyAdd)
	mux.HandleFunc("POST /api/policy/kind", s.handlePolicyKind)
	mux.HandleFunc("POST /api/row", s.handleRow)
	mux.HandleFunc("POST /api/row/delete", s.handleRowDelete)
	mux.HandleFunc("GET /events", s.handleEvents)

	ui, err := fs.Sub(uiFS, "ui")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServerFS(ui))

	return mux
}

type stateResponse struct {
	Error string              `json:"error,omitempty"`
	YAML  string              `json:"yaml"`
	Grid  []workspace.GridRow `json:"grid"`
	Rev   uint64              `json:"rev"`
}

func (s *server) handleState(w http.ResponseWriter, _ *http.Request) {
	s.writeState(w)
}

func (s *server) handleYAML(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	policies, err := parsePolicies(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.ws.Replace(r.Context(), policies); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.writeState(w)
}

type policyKindRequest struct {
	FQN  string `json:"fqn"`
	Kind string `json:"kind"`
}

func (s *server) handlePolicyAdd(w http.ResponseWriter, r *http.Request) {
	var req policyKindRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := workspace.AddPlaceholderPolicy(r.Context(), s.ws, req.Kind); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.writeState(w)
}

func (s *server) handlePolicyKind(w http.ResponseWriter, r *http.Request) {
	var req policyKindRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := workspace.SetPolicyKind(r.Context(), s.ws, req.FQN, req.Kind); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.writeState(w)
}

type rowRequest struct {
	Patch workspace.GridPatch  `json:"patch"`
	Key   workspace.GridRowKey `json:"key"`
}

func (s *server) handleRow(w http.ResponseWriter, r *http.Request) {
	var req rowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := workspace.ApplyGridMutation(r.Context(), s.ws, req.Key, req.Patch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.writeState(w)
}

type deleteRowRequest struct {
	Key workspace.GridRowKey `json:"key"`
}

func (s *server) handleRowDelete(w http.ResponseWriter, r *http.Request) {
	var req deleteRowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := workspace.DeleteGridRow(r.Context(), s.ws, req.Key); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.writeState(w)
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	events, unsub := s.ws.Subscribe()
	defer unsub()

	sendRev(w, flusher, s.ws.Snapshot().Rev)
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			sendRev(w, flusher, ev.Rev)
		}
	}
}

func sendRev(w io.Writer, flusher http.Flusher, rev uint64) {
	fmt.Fprintf(w, "data: {\"rev\":%d}\n\n", rev)
	flusher.Flush()
}

func (s *server) writeState(w http.ResponseWriter) {
	snap := s.ws.Snapshot()

	resp := stateResponse{Rev: snap.Rev, Grid: workspace.Grid(snap)}
	if snap.LastErr != nil {
		resp.Error = snap.LastErr.Error()
	}

	yaml, err := renderYAML(snap.Policies)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp.YAML = yaml

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func renderYAML(policies []*policyv1.Policy) (string, error) {
	var b strings.Builder
	for _, p := range policies {
		b.WriteString("---\n")
		if err := decompile.WriteYAML(&b, p); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func parsePolicies(data []byte) ([]*policyv1.Policy, error) {
	var out []*policyv1.Policy
	for _, doc := range splitYAMLDocuments(data) {
		p, _, err := policy.ReadPolicy(bytes.NewReader(doc))
		if err != nil {
			return nil, err
		}
		if p.GetApiVersion() == "" && p.GetPolicyType() == nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func splitYAMLDocuments(data []byte) [][]byte {
	var (
		docs [][]byte
		cur  []byte
	)
	flush := func() {
		if len(bytes.TrimSpace(cur)) > 0 {
			docs = append(docs, cur)
		}
		cur = nil
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, maxYAMLDocBytes)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "---" {
			flush()
			continue
		}
		cur = append(cur, sc.Bytes()...)
		cur = append(cur, '\n')
	}
	flush()

	return docs
}

// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/spf13/afero"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/decompile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/util"
)

var ErrClosed = errors.New("workspace is closed")

type Event struct {
	Rev uint64
}

type Snapshot struct {
	LastErr   error
	RuleTable *runtimev1.RuleTable
	Policies  []*policyv1.Policy
	Rev       uint64
}

type mutationKind int

const (
	mutationUpsert mutationKind = iota
	mutationDelete
	mutationReplace
)

type mutation struct {
	policy   *policyv1.Policy
	fqn      string
	policies []*policyv1.Policy
	kind     mutationKind
}

const dirMode fs.FileMode = 0o755

type state struct {
	protoRT   *runtimev1.RuleTable
	lastErr   error
	canonical []*policyv1.Policy
	rev       uint64
}

type Workspace struct {
	state       atomic.Pointer[state]
	schemaFiles map[string][]byte
	subscribers map[int]chan Event
	writeMu     sync.Mutex
	subMu       sync.Mutex
	nextSubID   int
	closed      atomic.Bool
}

func New(_ context.Context) (*Workspace, error) {
	return newWorkspace(nil, ruletable.NewProtoRuletable())
}

func FromDirectory(ctx context.Context, dir string) (*Workspace, error) {
	fsys, err := util.OpenDirectoryFS(dir)
	if err != nil {
		return nil, err
	}

	schemaFiles, err := readSchemaFiles(fsys)
	if err != nil {
		return nil, err
	}

	protoRT, err := compileFS(ctx, fsys)
	if err != nil {
		return nil, err
	}

	return newWorkspace(schemaFiles, protoRT)
}

func FromBundle(_ context.Context, r io.Reader) (*Workspace, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	protoRT := &runtimev1.RuleTable{}
	if err := protoRT.UnmarshalVT(data); err != nil {
		return nil, err
	}

	return newWorkspace(schemaFilesFromRuleTable(protoRT), protoRT)
}

func newWorkspace(schemaFiles map[string][]byte, protoRT *runtimev1.RuleTable) (*Workspace, error) {
	canonical, err := decompile.Decompile(protoRT)
	if err != nil {
		return nil, err
	}

	w := &Workspace{
		schemaFiles: schemaFiles,
		subscribers: make(map[int]chan Event),
	}
	w.state.Store(&state{protoRT: protoRT, canonical: canonical, rev: 1})

	return w, nil
}

func (w *Workspace) Upsert(ctx context.Context, p *policyv1.Policy) error {
	return w.submit(ctx, mutation{kind: mutationUpsert, policy: proto.Clone(p).(*policyv1.Policy)}) //nolint:forcetypeassert
}

func (w *Workspace) Delete(ctx context.Context, fqn string) error {
	return w.submit(ctx, mutation{kind: mutationDelete, fqn: fqn})
}

func (w *Workspace) Replace(ctx context.Context, policies []*policyv1.Policy) error {
	return w.submit(ctx, mutation{kind: mutationReplace, policies: clonePolicies(policies)})
}

func (w *Workspace) submit(ctx context.Context, m mutation) error {
	if w.closed.Load() {
		return ErrClosed
	}

	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return w.apply(ctx, m)
}

func (w *Workspace) apply(ctx context.Context, m mutation) error {
	cur := w.state.Load()

	protoRT, canonical, err := w.rebuild(ctx, nextPolicySet(cur, m))
	if err != nil {
		w.publishErr(cur, err)
		return err
	}

	rev := cur.rev + 1
	w.state.Store(&state{protoRT: protoRT, canonical: canonical, rev: rev})
	w.broadcast(rev)
	return nil
}

func (w *Workspace) publishErr(cur *state, err error) {
	w.state.Store(&state{protoRT: cur.protoRT, canonical: cur.canonical, rev: cur.rev, lastErr: err})
}

func nextPolicySet(cur *state, m mutation) []*policyv1.Policy {
	if m.kind == mutationReplace {
		return m.policies
	}

	current := cur.canonical

	switch m.kind {
	case mutationDelete:
		out := make([]*policyv1.Policy, 0, len(current))
		for _, p := range current {
			if namer.FQN(p) != m.fqn {
				out = append(out, p)
			}
		}
		return out
	default:
		fqn := namer.FQN(m.policy)
		out := make([]*policyv1.Policy, 0, len(current)+1)
		for _, p := range current {
			if namer.FQN(p) != fqn {
				out = append(out, p)
			}
		}
		return append(out, m.policy)
	}
}

func (w *Workspace) rebuild(ctx context.Context, policies []*policyv1.Policy) (*runtimev1.RuleTable, []*policyv1.Policy, error) {
	if err := checkUniqueFQNs(policies); err != nil {
		return nil, nil, err
	}

	fsys, err := w.buildFS(policies)
	if err != nil {
		return nil, nil, err
	}

	protoRT, err := compileFS(ctx, fsys)
	if err != nil {
		return nil, nil, err
	}

	canonical, err := decompile.Decompile(protoRT)
	if err != nil {
		return nil, nil, err
	}

	return protoRT, canonical, nil
}

func compileFS(ctx context.Context, fsys fs.FS) (*runtimev1.RuleTable, error) {
	idx, err := index.Build(ctx, fsys)
	if err != nil {
		return nil, err
	}
	defer idx.Close()

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	compiler, err := compile.NewManager(ctx, store)
	if err != nil {
		return nil, err
	}

	protoRT := ruletable.NewProtoRuletable()
	if err := ruletable.LoadPolicies(ctx, protoRT, compiler); err != nil {
		return nil, err
	}
	if err := ruletable.LoadSchemas(ctx, protoRT, store); err != nil {
		return nil, err
	}
	return protoRT, nil
}

func checkUniqueFQNs(policies []*policyv1.Policy) error {
	seen := make(map[string]struct{}, len(policies))
	for _, p := range policies {
		fqn := namer.FQN(p)
		if _, dup := seen[fqn]; dup {
			return fmt.Errorf("duplicate policy %s", fqn)
		}
		seen[fqn] = struct{}{}
	}
	return nil
}

func (w *Workspace) buildFS(policies []*policyv1.Policy) (fs.FS, error) {
	mem := afero.NewMemMapFs()
	if err := mem.MkdirAll(".", dirMode); err != nil {
		return nil, err
	}

	for p, content := range w.schemaFiles {
		if err := writeFile(mem, p, content); err != nil {
			return nil, err
		}
	}

	for _, p := range policies {
		var buf bytes.Buffer
		if err := policy.WritePolicy(&buf, p); err != nil {
			return nil, err
		}
		if err := writeFile(mem, namer.PolicyKey(p)+".yaml", buf.Bytes()); err != nil {
			return nil, err
		}
	}

	return afero.NewIOFS(mem), nil
}

func (w *Workspace) Snapshot() Snapshot {
	s := w.state.Load()
	return Snapshot{
		RuleTable: proto.Clone(s.protoRT).(*runtimev1.RuleTable), //nolint:forcetypeassert
		Policies:  clonePolicies(s.canonical),
		Rev:       s.rev,
		LastErr:   s.lastErr,
	}
}

func (w *Workspace) WriteBundle(out io.Writer) error {
	data, err := w.state.Load().protoRT.MarshalVT()
	if err != nil {
		return err
	}
	_, err = out.Write(data)
	return err
}

func (w *Workspace) Subscribe() (<-chan Event, func()) {
	w.subMu.Lock()
	defer w.subMu.Unlock()

	if w.closed.Load() {
		ch := make(chan Event)
		close(ch)
		return ch, func() {}
	}

	id := w.nextSubID
	w.nextSubID++
	ch := make(chan Event, 1)
	w.subscribers[id] = ch

	return ch, func() {
		w.subMu.Lock()
		defer w.subMu.Unlock()
		if c, ok := w.subscribers[id]; ok {
			close(c)
			delete(w.subscribers, id)
		}
	}
}

func (w *Workspace) broadcast(rev uint64) {
	w.subMu.Lock()
	defer w.subMu.Unlock()
	for _, ch := range w.subscribers {
		select {
		case <-ch:
		default:
		}
		ch <- Event{Rev: rev}
	}
}

func (w *Workspace) Close() error {
	if w.closed.Swap(true) {
		return nil
	}

	w.subMu.Lock()
	defer w.subMu.Unlock()
	for id, ch := range w.subscribers {
		close(ch)
		delete(w.subscribers, id)
	}
	return nil
}

func writeFile(mem afero.Fs, p string, content []byte) error {
	if dir := path.Dir(p); dir != "." {
		if err := mem.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}
	f, err := mem.Create(p)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func readSchemaFiles(fsys fs.FS) (map[string][]byte, error) {
	out := make(map[string][]byte)
	if _, err := fs.Stat(fsys, util.SchemasDirectory); err != nil {
		return out, nil //nolint:nilerr
	}

	err := fs.WalkDir(fsys, util.SchemasDirectory, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		content, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		out[p] = content
		return nil
	})
	return out, err
}

func schemaFilesFromRuleTable(rt *runtimev1.RuleTable) map[string][]byte {
	out := make(map[string][]byte)
	for ref, js := range rt.GetJsonSchemas() {
		u, err := url.Parse(ref)
		if err != nil || (u.Scheme != "" && u.Scheme != schema.URLScheme) {
			continue
		}
		out[path.Join(util.SchemasDirectory, strings.TrimPrefix(u.Path, "/"))] = js.GetContent()
	}
	return out
}

func clonePolicies(policies []*policyv1.Policy) []*policyv1.Policy {
	if policies == nil {
		return nil
	}
	out := make([]*policyv1.Policy, len(policies))
	for i, p := range policies {
		out[i] = proto.Clone(p).(*policyv1.Policy) //nolint:forcetypeassert
	}
	return out
}

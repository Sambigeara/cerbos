// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package workspace_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/workspace"
)

func TestBundleEngineEquivalence(t *testing.T) {
	ctx := t.Context()
	storeDir := test.PathToDir(t, "store")

	ws, err := workspace.FromDirectory(ctx, storeDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ws.Close() })

	var buf bytes.Buffer
	require.NoError(t, ws.WriteBundle(&buf))

	restored, err := workspace.FromBundle(ctx, &buf)
	require.NoError(t, err)
	t.Cleanup(func() { _ = restored.Close() })

	rt, err := ruletable.NewRuleTable(restored.Snapshot().RuleTable)
	require.NoError(t, err)

	evalConf := &evaluator.Conf{}
	evalConf.SetDefaults()
	evalConf.Globals = map[string]any{"environment": "test"}

	eval, err := rt.Evaluator(evalConf, schema.NewConf(schema.EnforcementNone))
	require.NoError(t, err)

	testCases := test.LoadTestCases(t, "engine")
	testCases = append(testCases, test.LoadTestCases(t, "engine_strict_scope_search")...)

	for _, tcase := range testCases {
		t.Run(tcase.Name, func(t *testing.T) {
			tc := test.Parse[privatev1.EngineTestCase](t, tcase.Input)

			traceCollector := tracer.NewCollector()
			haveOutputs, err := eval.Check(t.Context(), tc.Inputs, evaluator.WithTraceSink(traceCollector))

			if tc.WantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			for i, have := range haveOutputs {
				slices.SortStableFunc(have.Outputs, func(a, b *enginev1.OutputEntry) int {
					return strings.Compare(a.Src, b.Src)
				})

				require.Empty(t, cmp.Diff(tc.WantOutputs[i],
					have,
					protocmp.Transform(),
					protocmp.SortRepeatedFields(&enginev1.CheckOutput{}, "effective_derived_roles"),
				))
			}
		})
	}
}

// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package decompile_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/decompile"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

func TestEngineEquivalence(t *testing.T) {
	storeDir := test.PathToDir(t, "store")

	rt1 := buildRuleTable(t, storeDir)
	policies, err := decompile.Decompile(rt1)
	require.NoError(t, err)

	rt2Proto := buildRuleTable(t, recompileDir(t, policies, storeDir))
	rt2, err := ruletable.NewRuleTable(rt2Proto)
	require.NoError(t, err)

	evalConf := &evaluator.Conf{}
	evalConf.SetDefaults()
	evalConf.Globals = map[string]any{"environment": "test"}

	eval, err := rt2.Evaluator(evalConf, schema.NewConf(schema.EnforcementNone))
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

func buildRuleTable(t *testing.T, dir string) *runtimev1.RuleTable {
	t.Helper()
	ctx := t.Context()

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(t, err)

	rt := ruletable.NewProtoRuletable()
	require.NoError(t, ruletable.LoadPolicies(ctx, rt, compiler))
	require.NoError(t, ruletable.LoadSchemas(ctx, rt, store))

	return rt
}

func recompileDir(t *testing.T, policies []*policyv1.Policy, schemaSrcDir string) string {
	t.Helper()
	dir := t.TempDir()

	require.NoError(t, os.CopyFS(filepath.Join(dir, "_schemas"), os.DirFS(filepath.Join(schemaSrcDir, "_schemas"))))

	for _, p := range policies {
		path := filepath.Join(dir, namer.PolicyKey(p)+".yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		f, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, decompile.WriteYAML(f, p))
		require.NoError(t, f.Close())
	}

	return dir
}

func TestDecompilePreservesRuleTableValues(t *testing.T) {
	t.Run("scope permissions", func(t *testing.T) {
		row := resourceRow()
		row.ScopePermissions = policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT

		policy := decompileResourceRow(t, row)

		require.Equal(t, policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT, policy.GetScopePermissions())
	})

	t.Run("resource rule name", func(t *testing.T) {
		row := resourceRow()
		row.Name = "rule-001"

		policy := decompileResourceRow(t, row)

		require.Equal(t, "rule-001", policy.GetRules()[0].GetName())
	})

	t.Run("principal rule name", func(t *testing.T) {
		row := &runtimev1.RuleTable_RuleRow{
			OriginFqn: "cerbos.principal.alice.vdefault",
			Resource:  "album",
			ActionSet: &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
			Effect:    effectv1.Effect_EFFECT_ALLOW,
			Name:      "album_rule-001",
		}

		require.Equal(t, "album_rule-001", decompilePrincipalRow(t, row).GetRules()[0].GetActions()[0].GetName())
	})

	t.Run("principal rule name invalid in source", func(t *testing.T) {
		row := &runtimev1.RuleTable_RuleRow{
			OriginFqn: "cerbos.principal.alice.vdefault",
			Resource:  "album:object",
			ActionSet: &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
			Effect:    effectv1.Effect_EFFECT_ALLOW,
			Name:      "album:object_rule-001",
		}

		require.Empty(t, decompilePrincipalRow(t, row).GetRules()[0].GetActions()[0].GetName())
	})

	t.Run("effect and condition", func(t *testing.T) {
		row := resourceRow()
		row.ScopePermissions = policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
		row.Effect = effectv1.Effect_EFFECT_DENY
		row.Condition = &runtimev1.Condition{
			Op: &runtimev1.Condition_None{None: &runtimev1.Condition_ExprList{
				Expr: []*runtimev1.Condition{{
					Op: &runtimev1.Condition_Expr{Expr: &runtimev1.Expr{Original: "request.resource.attr.public"}},
				}},
			}},
		}

		policy := decompileResourceRow(t, row)
		rule := policy.GetRules()[0]

		require.Equal(t, effectv1.Effect_EFFECT_DENY, rule.GetEffect())
		require.Equal(t, "request.resource.attr.public", rule.GetCondition().GetMatch().GetNone().GetOf()[0].GetExpr())
	})
}

func resourceRow() *runtimev1.RuleTable_RuleRow {
	return &runtimev1.RuleTable_RuleRow{
		OriginFqn: "cerbos.resource.album.vdefault",
		Resource:  "album",
		ActionSet: &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
		Effect:    effectv1.Effect_EFFECT_ALLOW,
	}
}

func decompileResourceRow(t *testing.T, row *runtimev1.RuleTable_RuleRow) *policyv1.ResourcePolicy {
	t.Helper()
	rt := &runtimev1.RuleTable{
		Rules: []*runtimev1.RuleTable_RuleRow{row},
		Meta: map[uint64]*runtimev1.RuleTableMetadata{
			1: {
				Fqn:     row.GetOriginFqn(),
				Name:    &runtimev1.RuleTableMetadata_Resource{Resource: row.GetResource()},
				Version: "default",
			},
		},
	}

	policies, err := decompile.Decompile(rt)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	return policies[0].GetResourcePolicy()
}

func decompilePrincipalRow(t *testing.T, row *runtimev1.RuleTable_RuleRow) *policyv1.PrincipalPolicy {
	t.Helper()
	rt := &runtimev1.RuleTable{
		Rules: []*runtimev1.RuleTable_RuleRow{row},
		Meta: map[uint64]*runtimev1.RuleTableMetadata{
			1: {
				Fqn:     row.GetOriginFqn(),
				Name:    &runtimev1.RuleTableMetadata_Principal{Principal: "alice"},
				Version: "default",
			},
		},
	}

	policies, err := decompile.Decompile(rt)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	return policies[0].GetPrincipalPolicy()
}

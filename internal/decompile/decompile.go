// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package decompile

import (
	"bytes"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	structpb "google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

const apiVersion = "api.cerbos.dev/v1"

var (
	principalAutoRuleName = regexp.MustCompile(`_rule-\d{3,}$`)
	validRuleName         = regexp.MustCompile(`^([a-zA-Z][\w@.\-]*)?$`)
)

func Decompile(rt *runtimev1.RuleTable) ([]*policyv1.Policy, error) {
	out := decompileDerivedRolesFiles(rt)

	rowsByFQN := make(map[string][]*runtimev1.RuleTable_RuleRow)
	for _, r := range rt.GetRules() {
		rowsByFQN[r.GetOriginFqn()] = append(rowsByFQN[r.GetOriginFqn()], r)
	}

	// Parent-role-only policies have metadata but no rows.
	for modID, meta := range rt.GetMeta() {
		rows := rowsByFQN[meta.GetFqn()]

		var (
			p   *policyv1.Policy
			err error
		)
		switch meta.GetName().(type) {
		case *runtimev1.RuleTableMetadata_Resource:
			p = decompileResourcePolicy(rt, modID, meta, rows)
		case *runtimev1.RuleTableMetadata_Principal:
			p = decompilePrincipalPolicy(meta, rows)
		case *runtimev1.RuleTableMetadata_Role:
			p = decompileRolePolicy(rt, meta, rows)
		default:
			err = fmt.Errorf("rule table metadata for %q has no policy kind", meta.GetFqn())
		}
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}

	for _, p := range out {
		sortPolicy(p)
	}
	slices.SortFunc(out, func(a, b *policyv1.Policy) int {
		return cmpString(namer.FQN(a), namer.FQN(b))
	})

	return out, nil
}

func decompileResourcePolicy(
	rt *runtimev1.RuleTable,
	modID uint64,
	meta *runtimev1.RuleTableMetadata,
	rows []*runtimev1.RuleTable_RuleRow,
) *policyv1.Policy {
	rp := &policyv1.ResourcePolicy{
		Resource: meta.GetResource(),
		Version:  meta.GetVersion(),
		Scope:    scopeOf(rows, meta.GetFqn()),
	}
	if s, ok := rt.GetSchemas()[modID]; ok {
		rp.Schemas = s
	}

	var scopePermissions policyv1.ScopePermissions
	if len(rows) > 0 {
		scopePermissions = rows[0].GetScopePermissions()
	}
	rp.ScopePermissions = scopePermissions
	rp.Rules = foldResourceRules(rows)

	params := paramsOf(rows)
	rp.Variables = decompileVariables(params.GetOrderedVariables())
	rp.Constants = decompileConstants(params.GetConstants())
	rp.ImportDerivedRoles = recoverImportDerivedRoles(rt.GetPolicyDerivedRoles()[modID])

	return &policyv1.Policy{
		ApiVersion: apiVersion,
		Metadata:   metadataFor(meta.GetAnnotations()),
		PolicyType: &policyv1.Policy_ResourcePolicy{ResourcePolicy: rp},
	}
}

type roleRef struct {
	name    string
	derived bool
}

func foldResourceRules(rows []*runtimev1.RuleTable_RuleRow) []*policyv1.ResourceRule {
	type bucket struct {
		condition *runtimev1.Condition
		output    *runtimev1.Output
		actions   map[roleRef]map[string]struct{}
		name      string
		effect    effectv1.Effect
	}
	buckets := make(map[string]*bucket)
	for _, r := range rows {
		if r.GetEffect() == effectv1.Effect_EFFECT_UNSPECIFIED {
			continue
		}
		effect, condition := r.GetEffect(), r.GetCondition()
		name := r.GetName()
		key := ruleBucketKey(name, effect, condition, r.GetEmitOutput())
		b := buckets[key]
		if b == nil {
			b = &bucket{effect: effect, condition: condition, output: r.GetEmitOutput(), name: name, actions: map[roleRef]map[string]struct{}{}}
			buckets[key] = b
		}

		ref := roleRef{name: r.GetRole()}
		if dr := r.GetOriginDerivedRole(); dr != "" {
			ref = roleRef{derived: true, name: dr}
		}
		if b.actions[ref] == nil {
			b.actions[ref] = map[string]struct{}{}
		}
		if act := r.GetAction(); act != "" {
			b.actions[ref][act] = struct{}{}
		}
	}

	rules := make([]*policyv1.ResourceRule, 0, len(buckets))
	for _, b := range buckets {
		type group struct {
			actions []string
			refs    []roleRef
		}
		groups := make(map[string]*group)
		for ref, acts := range b.actions {
			sorted := setToSlice(acts)
			gk := strings.Join(sorted, "\x00")
			g := groups[gk]
			if g == nil {
				g = &group{actions: sorted}
				groups[gk] = g
			}
			g.refs = append(g.refs, ref)
		}
		for _, g := range groups {
			var roles, derived []string
			for _, ref := range g.refs {
				switch {
				case ref.derived:
					derived = append(derived, ref.name)
				case ref.name != "":
					roles = append(roles, ref.name)
				}
			}
			rules = append(rules, &policyv1.ResourceRule{
				Actions:      g.actions,
				Roles:        roles,
				DerivedRoles: derived,
				Effect:       b.effect,
				Condition:    decompileCondition(b.condition),
				Name:         b.name,
				Output:       decompileOutput(b.output),
			})
		}
	}
	return rules
}

func ruleBucketKey(name string, effect effectv1.Effect, condition *runtimev1.Condition, output *runtimev1.Output) string {
	var b bytes.Buffer
	b.WriteString(name)
	b.WriteByte(0)
	b.WriteString(effect.String())
	b.WriteByte(0)
	b.Write(detMarshal(condition))
	b.WriteByte(0)
	b.Write(detMarshal(output))
	return b.String()
}

func detMarshal(m proto.Message) []byte {
	if m == nil || !m.ProtoReflect().IsValid() {
		return nil
	}
	out, _ := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	return out
}

func decompilePrincipalPolicy(
	meta *runtimev1.RuleTableMetadata,
	rows []*runtimev1.RuleTable_RuleRow,
) *policyv1.Policy {
	pp := &policyv1.PrincipalPolicy{
		Principal: meta.GetPrincipal(),
		Version:   meta.GetVersion(),
		Scope:     scopeOf(rows, meta.GetFqn()),
	}

	var scopePermissions policyv1.ScopePermissions
	if len(rows) > 0 {
		scopePermissions = rows[0].GetScopePermissions()
	}
	pp.ScopePermissions = scopePermissions

	byResource := make(map[string]*policyv1.PrincipalRule)
	var order []string
	for _, r := range rows {
		if r.GetEffect() == effectv1.Effect_EFFECT_UNSPECIFIED {
			continue
		}
		rule := byResource[r.GetResource()]
		if rule == nil {
			rule = &policyv1.PrincipalRule{Resource: r.GetResource()}
			byResource[r.GetResource()] = rule
			order = append(order, r.GetResource())
		}
		rule.Actions = append(rule.Actions, &policyv1.PrincipalRule_Action{
			Action:    r.GetAction(),
			Effect:    r.GetEffect(),
			Condition: decompileCondition(r.GetCondition()),
			Name:      decompilePrincipalRuleName(r.GetName()),
			Output:    decompileOutput(r.GetEmitOutput()),
		})
	}
	for _, resource := range order {
		pp.Rules = append(pp.Rules, byResource[resource])
	}

	params := paramsOf(rows)
	pp.Variables = decompileVariables(params.GetOrderedVariables())
	pp.Constants = decompileConstants(params.GetConstants())

	return &policyv1.Policy{
		ApiVersion: apiVersion,
		Metadata:   metadataFor(meta.GetAnnotations()),
		PolicyType: &policyv1.Policy_PrincipalPolicy{PrincipalPolicy: pp},
	}
}

func decompileRolePolicy(
	rt *runtimev1.RuleTable,
	meta *runtimev1.RuleTableMetadata,
	rows []*runtimev1.RuleTable_RuleRow,
) *policyv1.Policy {
	scope := scopeOf(rows, meta.GetFqn())
	rp := &policyv1.RolePolicy{
		PolicyType: &policyv1.RolePolicy_Role{Role: meta.GetRole()},
		Version:    meta.GetVersion(),
		Scope:      scope,
	}

	if spr := rt.GetScopeParentRoles()[scope]; spr != nil {
		if pr := spr.GetRoleParentRoles()[meta.GetRole()]; pr != nil {
			rp.ParentRoles = append([]string(nil), pr.GetRoles()...)
		}
	}

	for _, r := range rows {
		rp.Rules = append(rp.Rules, &policyv1.RoleRule{
			Resource:     r.GetResource(),
			AllowActions: setToSlice(r.GetAllowActions().GetActions()),
			Condition:    decompileCondition(r.GetCondition()),
			Name:         r.GetName(),
			Output:       decompileOutput(r.GetEmitOutput()),
		})
	}

	params := paramsOf(rows)
	rp.Variables = decompileVariables(params.GetOrderedVariables())
	rp.Constants = decompileConstants(params.GetConstants())

	return &policyv1.Policy{
		ApiVersion: apiVersion,
		Metadata:   metadataFor(meta.GetAnnotations()),
		PolicyType: &policyv1.Policy_RolePolicy{RolePolicy: rp},
	}
}

func decompileCondition(c *runtimev1.Condition) *policyv1.Condition {
	m := matchFromCondition(c)
	if m == nil {
		return nil
	}
	return &policyv1.Condition{Condition: &policyv1.Condition_Match{Match: m}}
}

func matchFromCondition(c *runtimev1.Condition) *policyv1.Match {
	switch op := c.GetOp().(type) {
	case *runtimev1.Condition_Expr:
		return &policyv1.Match{Op: &policyv1.Match_Expr{Expr: op.Expr.GetOriginal()}}
	case *runtimev1.Condition_All:
		return &policyv1.Match{Op: &policyv1.Match_All{All: exprListFromCondition(op.All)}}
	case *runtimev1.Condition_Any:
		return &policyv1.Match{Op: &policyv1.Match_Any{Any: exprListFromCondition(op.Any)}}
	case *runtimev1.Condition_None:
		return &policyv1.Match{Op: &policyv1.Match_None{None: exprListFromCondition(op.None)}}
	default:
		return nil
	}
}

func exprListFromCondition(l *runtimev1.Condition_ExprList) *policyv1.Match_ExprList {
	out := &policyv1.Match_ExprList{Of: make([]*policyv1.Match, 0, len(l.GetExpr()))}
	for _, c := range l.GetExpr() {
		out.Of = append(out.Of, matchFromCondition(c))
	}
	return out
}

func decompileOutput(o *runtimev1.Output) *policyv1.Output {
	when := o.GetWhen()
	if when == nil {
		return nil
	}
	ruleActivated := when.GetRuleActivated().GetOriginal()
	conditionNotMet := when.GetConditionNotMet().GetOriginal()
	if ruleActivated == "" && conditionNotMet == "" {
		return nil
	}
	return &policyv1.Output{When: &policyv1.Output_When{RuleActivated: ruleActivated, ConditionNotMet: conditionNotMet}}
}

func decompileVariables(ordered []*runtimev1.Variable) *policyv1.Variables {
	if len(ordered) == 0 {
		return nil
	}
	local := make(map[string]string, len(ordered))
	for _, v := range ordered {
		local[v.GetName()] = v.GetExpr().GetOriginal()
	}
	return &policyv1.Variables{Local: local}
}

func decompileConstants(consts map[string]*structpb.Value) *policyv1.Constants {
	if len(consts) == 0 {
		return nil
	}
	local := make(map[string]*structpb.Value, len(consts))
	maps.Copy(local, consts)
	return &policyv1.Constants{Local: local}
}

func recoverImportDerivedRoles(pdr *runtimev1.RuleTable_PolicyDerivedRoles) []string {
	if pdr == nil {
		return nil
	}
	set := make(map[string]struct{})
	for _, rdr := range pdr.GetDerivedRoles() {
		set[namer.SimpleName(rdr.GetOriginFqn())] = struct{}{}
	}
	return setToSlice(set)
}

func decompileDerivedRolesFiles(rt *runtimev1.RuleTable) []*policyv1.Policy {
	type drFile struct {
		defs      map[string]*runtimev1.RunnableDerivedRole
		variables map[string]string
		constants map[string]*structpb.Value
	}
	files := make(map[string]*drFile)
	for _, pdr := range rt.GetPolicyDerivedRoles() {
		for _, rdr := range pdr.GetDerivedRoles() {
			f := files[rdr.GetOriginFqn()]
			if f == nil {
				f = &drFile{
					defs:      make(map[string]*runtimev1.RunnableDerivedRole),
					variables: make(map[string]string),
					constants: make(map[string]*structpb.Value),
				}
				files[rdr.GetOriginFqn()] = f
			}
			f.defs[rdr.GetName()] = rdr
			for _, v := range rdr.GetOrderedVariables() {
				f.variables[v.GetName()] = v.GetExpr().GetOriginal()
			}
			maps.Copy(f.constants, rdr.GetConstants())
		}
	}

	out := make([]*policyv1.Policy, 0, len(files))
	for fqn, f := range files {
		dr := &policyv1.DerivedRoles{Name: namer.SimpleName(fqn)}
		for _, name := range setToSlice(f.defs) {
			rdr := f.defs[name]
			dr.Definitions = append(dr.Definitions, &policyv1.RoleDef{
				Name:        rdr.GetName(),
				ParentRoles: setToSlice(rdr.GetParentRoles()),
				Condition:   decompileCondition(rdr.GetCondition()),
			})
		}
		if len(f.variables) > 0 {
			dr.Variables = &policyv1.Variables{Local: f.variables}
		}
		if len(f.constants) > 0 {
			dr.Constants = &policyv1.Constants{Local: f.constants}
		}
		out = append(out, &policyv1.Policy{
			ApiVersion: apiVersion,
			PolicyType: &policyv1.Policy_DerivedRoles{DerivedRoles: dr},
		})
	}
	return out
}

func metadataFor(annotations map[string]string) *policyv1.Metadata {
	if len(annotations) == 0 {
		return nil
	}
	return &policyv1.Metadata{Annotations: annotations}
}

func decompilePrincipalRuleName(name string) string {
	if principalAutoRuleName.MatchString(name) && !validRuleName.MatchString(name) {
		return ""
	}
	return name
}

func paramsOf(rows []*runtimev1.RuleTable_RuleRow) *runtimev1.RuleTable_RuleRow_Params {
	if len(rows) == 0 {
		return nil
	}
	return rows[0].GetParams()
}

// FQNs are ambiguous when names contain slashes; only use one when no row exists.
func scopeOf(rows []*runtimev1.RuleTable_RuleRow, fqn string) string {
	if len(rows) > 0 {
		return rows[0].GetScope()
	}
	return namer.ScopeFromFQN(fqn)
}

func setToSlice[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func sortPolicy(p *policyv1.Policy) {
	switch pt := p.GetPolicyType().(type) {
	case *policyv1.Policy_ResourcePolicy:
		sortResourcePolicy(pt.ResourcePolicy)
	case *policyv1.Policy_PrincipalPolicy:
		sortPrincipalPolicy(pt.PrincipalPolicy)
	case *policyv1.Policy_RolePolicy:
		sortRolePolicy(pt.RolePolicy)
	case *policyv1.Policy_DerivedRoles:
		sortDerivedRoles(pt.DerivedRoles)
	}
}

func sortResourcePolicy(rp *policyv1.ResourcePolicy) {
	slices.Sort(rp.ImportDerivedRoles)
	for _, rule := range rp.Rules {
		slices.Sort(rule.Actions)
		slices.Sort(rule.Roles)
		slices.Sort(rule.DerivedRoles)
	}
	sortByKey(rp.Rules)
}

func sortPrincipalPolicy(pp *policyv1.PrincipalPolicy) {
	for _, rule := range pp.Rules {
		sortByKey(rule.Actions)
	}
	sortByKey(pp.Rules)
}

func sortRolePolicy(rp *policyv1.RolePolicy) {
	slices.Sort(rp.ParentRoles)
	for _, rule := range rp.Rules {
		slices.Sort(rule.AllowActions)
	}
	sortByKey(rp.Rules)
}

func sortDerivedRoles(dr *policyv1.DerivedRoles) {
	for _, def := range dr.Definitions {
		slices.Sort(def.ParentRoles)
	}
	sortByKey(dr.Definitions)
}

func sortByKey[M proto.Message](msgs []M) {
	slices.SortFunc(msgs, func(a, b M) int {
		ka, _ := proto.MarshalOptions{Deterministic: true}.Marshal(a)
		kb, _ := proto.MarshalOptions{Deterministic: true}.Marshal(b)
		return bytes.Compare(ka, kb)
	})
}

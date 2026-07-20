// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

const (
	apiVersion     = "api.cerbos.dev/v1"
	defaultVersion = "default"

	kindResource  = "resource"
	kindPrincipal = "principal"
	kindRole      = "role"

	placeholderAction   = "action"
	placeholderRole     = "role"
	placeholderResource = "resource"
)

type GridRow struct {
	PolicyKind  string
	PolicyFQN   string
	Scope       string
	Resource    string
	Principal   string
	Role        string
	DerivedRole string
	Action      string
	Effect      string
	Condition   string
	Name        string
	Key         GridRowKey
}

// GridRowKey is only stable within one snapshot.
type GridRowKey struct {
	PolicyFQN        string
	RuleIndex        int
	ActionIndex      int
	RoleIndex        int
	DerivedRoleIndex int
}

// Nil fields are left unchanged.
type GridPatch struct {
	Action      *string
	Role        *string
	DerivedRole *string
	Effect      *string
	Resource    *string
	Scope       *string
	Condition   *string
}

func Grid(snap Snapshot) []GridRow {
	var rows []GridRow
	for _, p := range snap.Policies {
		switch pt := p.GetPolicyType().(type) {
		case *policyv1.Policy_ResourcePolicy:
			rows = append(rows, resourceGridRows(p, pt.ResourcePolicy)...)
		case *policyv1.Policy_PrincipalPolicy:
			rows = append(rows, principalGridRows(p, pt.PrincipalPolicy)...)
		case *policyv1.Policy_RolePolicy:
			rows = append(rows, roleGridRows(p, pt.RolePolicy)...)
		}
	}
	return rows
}

func resourceGridRows(p *policyv1.Policy, rp *policyv1.ResourcePolicy) []GridRow {
	fqn := namer.FQN(p)
	var rows []GridRow
	for ri, rule := range rp.GetRules() {
		base := GridRow{
			PolicyKind: kindResource,
			PolicyFQN:  fqn,
			Scope:      rp.GetScope(),
			Resource:   rp.GetResource(),
			Effect:     rule.GetEffect().String(),
			Condition:  conditionText(rule.GetCondition()),
			Name:       rule.GetName(),
		}
		for ai, action := range rule.GetActions() {
			for roi, role := range rule.GetRoles() {
				row := base
				row.Key = GridRowKey{PolicyFQN: fqn, RuleIndex: ri, ActionIndex: ai, RoleIndex: roi, DerivedRoleIndex: -1}
				row.Action = action
				row.Role = role
				rows = append(rows, row)
			}
			for di, dr := range rule.GetDerivedRoles() {
				row := base
				row.Key = GridRowKey{PolicyFQN: fqn, RuleIndex: ri, ActionIndex: ai, RoleIndex: -1, DerivedRoleIndex: di}
				row.Action = action
				row.DerivedRole = dr
				rows = append(rows, row)
			}
		}
	}
	return rows
}

func principalGridRows(p *policyv1.Policy, pp *policyv1.PrincipalPolicy) []GridRow {
	fqn := namer.FQN(p)
	var rows []GridRow
	for ri, rule := range pp.GetRules() {
		for ai, action := range rule.GetActions() {
			rows = append(rows, GridRow{
				Key:        GridRowKey{PolicyFQN: fqn, RuleIndex: ri, ActionIndex: ai, RoleIndex: -1, DerivedRoleIndex: -1},
				PolicyKind: kindPrincipal,
				PolicyFQN:  fqn,
				Scope:      pp.GetScope(),
				Principal:  pp.GetPrincipal(),
				Resource:   rule.GetResource(),
				Action:     action.GetAction(),
				Effect:     action.GetEffect().String(),
				Condition:  conditionText(action.GetCondition()),
				Name:       action.GetName(),
			})
		}
	}
	return rows
}

func roleGridRows(p *policyv1.Policy, rp *policyv1.RolePolicy) []GridRow {
	fqn := namer.FQN(p)
	var rows []GridRow
	for ri, rule := range rp.GetRules() {
		for ai, action := range rule.GetAllowActions() {
			rows = append(rows, GridRow{
				Key:        GridRowKey{PolicyFQN: fqn, RuleIndex: ri, ActionIndex: ai, RoleIndex: -1, DerivedRoleIndex: -1},
				PolicyKind: kindRole,
				PolicyFQN:  fqn,
				Scope:      rp.GetScope(),
				Role:       rp.GetRole(),
				Resource:   rule.GetResource(),
				Action:     action,
				Condition:  conditionText(rule.GetCondition()),
				Name:       rule.GetName(),
			})
		}
	}
	return rows
}

func ApplyGridMutation(ctx context.Context, w *Workspace, key GridRowKey, patch GridPatch) error {
	set := w.Snapshot().Policies
	target := findPolicy(set, key.PolicyFQN)
	if target == nil {
		return fmt.Errorf("no policy with FQN %q", key.PolicyFQN)
	}

	newName, newScope := policyName(target), policyScope(target)
	if patch.Scope != nil {
		newScope = *patch.Scope
	}
	switch target.GetPolicyType().(type) {
	case *policyv1.Policy_ResourcePolicy:
		if patch.Resource != nil {
			newName = *patch.Resource
		}
	case *policyv1.Policy_RolePolicy:
		if patch.Role != nil {
			newName = *patch.Role
		}
	}
	if newName != policyName(target) || newScope != policyScope(target) {
		next, err := moveCell(set, target, key, newName, newScope)
		if err != nil {
			return err
		}
		return w.Replace(ctx, next)
	}

	switch pt := target.GetPolicyType().(type) {
	case *policyv1.Policy_ResourcePolicy:
		if err := patchResourcePolicy(pt.ResourcePolicy, key, patch); err != nil {
			return err
		}
	case *policyv1.Policy_PrincipalPolicy:
		if err := patchPrincipalPolicy(pt.PrincipalPolicy, key, patch); err != nil {
			return err
		}
	case *policyv1.Policy_RolePolicy:
		if err := patchRolePolicy(pt.RolePolicy, key, patch); err != nil {
			return err
		}
	default:
		return fmt.Errorf("policy %q is not editable via the grid", key.PolicyFQN)
	}

	return w.Replace(ctx, set)
}

func moveCell(set []*policyv1.Policy, target *policyv1.Policy, key GridRowKey, newName, newScope string) ([]*policyv1.Policy, error) {
	switch pt := target.GetPolicyType().(type) {
	case *policyv1.Policy_ResourcePolicy:
		rp := pt.ResourcePolicy
		rule, err := indexInto(rp.GetRules(), key.RuleIndex, "rule")
		if err != nil {
			return nil, err
		}
		moved, remainder, err := carveResourceCell(rule, key)
		if err != nil {
			return nil, err
		}
		rp.Rules = spliceRules(rp.GetRules(), key.RuleIndex, remainder)
		next, dst := findOrCreateScopedResource(set, newName, rp.GetVersion(), newScope)
		dst.Rules = append(dst.Rules, moved)
		return dropIfEmpty(next, target), nil

	case *policyv1.Policy_PrincipalPolicy:
		pp := pt.PrincipalPolicy
		rule, err := indexInto(pp.GetRules(), key.RuleIndex, "rule")
		if err != nil {
			return nil, err
		}
		action, err := indexInto(rule.GetActions(), key.ActionIndex, "action")
		if err != nil {
			return nil, err
		}
		moved := clonePrincipalAction(action)
		resource := rule.GetResource()
		rule.Actions = append(rule.Actions[:key.ActionIndex], rule.Actions[key.ActionIndex+1:]...)
		if len(rule.Actions) == 0 {
			pp.Rules = append(pp.Rules[:key.RuleIndex], pp.Rules[key.RuleIndex+1:]...)
		}
		next, dst := findOrCreateScopedPrincipal(set, newName, pp.GetVersion(), newScope)
		appendPrincipalAction(dst, resource, moved)
		return dropIfEmpty(next, target), nil

	case *policyv1.Policy_RolePolicy:
		rp := pt.RolePolicy
		rule, err := indexInto(rp.GetRules(), key.RuleIndex, "rule")
		if err != nil {
			return nil, err
		}
		allowAction, err := indexInto(rule.GetAllowActions(), key.ActionIndex, "allow action")
		if err != nil {
			return nil, err
		}
		moved := proto.Clone(rule).(*policyv1.RoleRule) //nolint:forcetypeassert
		moved.AllowActions, moved.Name = []string{allowAction}, ""
		rule.AllowActions = append(rule.AllowActions[:key.ActionIndex], rule.AllowActions[key.ActionIndex+1:]...)
		if len(rule.AllowActions) == 0 {
			rp.Rules = append(rp.Rules[:key.RuleIndex], rp.Rules[key.RuleIndex+1:]...)
		}
		next, dst := findOrCreateScopedRole(set, newName, rp.GetVersion(), newScope)
		dst.Rules = append(dst.Rules, moved)
		return dropIfEmpty(next, target), nil

	default:
		return nil, fmt.Errorf("policy %q is not editable via the grid", key.PolicyFQN)
	}
}

func clonePrincipalAction(a *policyv1.PrincipalRule_Action) *policyv1.PrincipalRule_Action {
	c := proto.Clone(a).(*policyv1.PrincipalRule_Action) //nolint:forcetypeassert
	c.Name = ""
	return c
}

func appendPrincipalAction(pp *policyv1.PrincipalPolicy, resource string, action *policyv1.PrincipalRule_Action) {
	for _, r := range pp.Rules {
		if r.GetResource() == resource {
			r.Actions = append(r.Actions, action)
			return
		}
	}
	pp.Rules = append(pp.Rules, &policyv1.PrincipalRule{Resource: resource, Actions: []*policyv1.PrincipalRule_Action{action}})
}

func findOrCreateScopedResource(set []*policyv1.Policy, resource, version, scope string) ([]*policyv1.Policy, *policyv1.ResourcePolicy) {
	for _, p := range set {
		if rp := p.GetResourcePolicy(); rp != nil && rp.GetResource() == resource && rp.GetVersion() == version && rp.GetScope() == scope {
			return set, rp
		}
	}
	rp := &policyv1.ResourcePolicy{Resource: resource, Version: version, Scope: scope}
	return append(set, &policyv1.Policy{ApiVersion: apiVersion, PolicyType: &policyv1.Policy_ResourcePolicy{ResourcePolicy: rp}}), rp
}

func findOrCreateScopedPrincipal(set []*policyv1.Policy, principal, version, scope string) ([]*policyv1.Policy, *policyv1.PrincipalPolicy) {
	for _, p := range set {
		if pp := p.GetPrincipalPolicy(); pp != nil && pp.GetPrincipal() == principal && pp.GetVersion() == version && pp.GetScope() == scope {
			return set, pp
		}
	}
	pp := &policyv1.PrincipalPolicy{Principal: principal, Version: version, Scope: scope}
	return append(set, &policyv1.Policy{ApiVersion: apiVersion, PolicyType: &policyv1.Policy_PrincipalPolicy{PrincipalPolicy: pp}}), pp
}

func findOrCreateScopedRole(set []*policyv1.Policy, role, version, scope string) ([]*policyv1.Policy, *policyv1.RolePolicy) {
	for _, p := range set {
		if rp := p.GetRolePolicy(); rp != nil && rp.GetRole() == role && rp.GetVersion() == version && rp.GetScope() == scope {
			return set, rp
		}
	}
	rp := &policyv1.RolePolicy{PolicyType: &policyv1.RolePolicy_Role{Role: role}, Version: version, Scope: scope}
	return append(set, &policyv1.Policy{ApiVersion: apiVersion, PolicyType: &policyv1.Policy_RolePolicy{RolePolicy: rp}}), rp
}

func policyScope(p *policyv1.Policy) string {
	switch pt := p.GetPolicyType().(type) {
	case *policyv1.Policy_ResourcePolicy:
		return pt.ResourcePolicy.GetScope()
	case *policyv1.Policy_PrincipalPolicy:
		return pt.PrincipalPolicy.GetScope()
	case *policyv1.Policy_RolePolicy:
		return pt.RolePolicy.GetScope()
	default:
		return ""
	}
}

func policyHasContent(p *policyv1.Policy) bool {
	switch pt := p.GetPolicyType().(type) {
	case *policyv1.Policy_ResourcePolicy:
		return len(pt.ResourcePolicy.GetRules()) > 0 || pt.ResourcePolicy.GetSchemas() != nil
	case *policyv1.Policy_PrincipalPolicy:
		return len(pt.PrincipalPolicy.GetRules()) > 0
	case *policyv1.Policy_RolePolicy:
		return len(pt.RolePolicy.GetRules()) > 0 || len(pt.RolePolicy.GetParentRoles()) > 0
	default:
		return true
	}
}

func dropIfEmpty(set []*policyv1.Policy, p *policyv1.Policy) []*policyv1.Policy {
	if policyHasContent(p) {
		return set
	}
	out := make([]*policyv1.Policy, 0, len(set))
	for _, x := range set {
		if x != p {
			out = append(out, x)
		}
	}
	return out
}

func AddPlaceholderPolicy(ctx context.Context, w *Workspace, kind string) error {
	if kind == "" {
		kind = kindResource
	}
	set := w.Snapshot().Policies
	p, err := placeholderPolicy(kind, freePolicyName(set, kind))
	if err != nil {
		return err
	}
	return w.Replace(ctx, append(set, p))
}

func freePolicyName(set []*policyv1.Policy, kind string) string {
	used := make(map[string]bool)
	for _, p := range set {
		if policyKind(p) == kind {
			used[policyName(p)] = true
		}
	}
	if !used[kind] {
		return kind
	}
	for i := 2; ; i++ {
		if n := fmt.Sprintf("%s%d", kind, i); !used[n] {
			return n
		}
	}
}

func SetPolicyKind(ctx context.Context, w *Workspace, fqn, kind string) error {
	set := w.Snapshot().Policies
	idx := -1
	for i, p := range set {
		if namer.FQN(p) == fqn {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("no policy with FQN %q", fqn)
	}
	if policyKind(set[idx]) == kind {
		return nil
	}

	p, err := placeholderPolicy(kind, policyName(set[idx]))
	if err != nil {
		return err
	}
	set[idx] = p
	return w.Replace(ctx, set)
}

func placeholderPolicy(kind, name string) (*policyv1.Policy, error) {
	switch kind {
	case kindResource:
		return &policyv1.Policy{ApiVersion: apiVersion, PolicyType: &policyv1.Policy_ResourcePolicy{ResourcePolicy: &policyv1.ResourcePolicy{
			Resource: name,
			Version:  defaultVersion,
			Rules:    []*policyv1.ResourceRule{{Actions: []string{placeholderAction}, Roles: []string{placeholderRole}, Effect: effectv1.Effect_EFFECT_ALLOW}},
		}}}, nil
	case kindPrincipal:
		return &policyv1.Policy{ApiVersion: apiVersion, PolicyType: &policyv1.Policy_PrincipalPolicy{PrincipalPolicy: &policyv1.PrincipalPolicy{
			Principal: name,
			Version:   defaultVersion,
			Rules:     []*policyv1.PrincipalRule{{Resource: placeholderResource, Actions: []*policyv1.PrincipalRule_Action{{Action: placeholderAction, Effect: effectv1.Effect_EFFECT_ALLOW}}}},
		}}}, nil
	case kindRole:
		return &policyv1.Policy{ApiVersion: apiVersion, PolicyType: &policyv1.Policy_RolePolicy{RolePolicy: &policyv1.RolePolicy{
			PolicyType: &policyv1.RolePolicy_Role{Role: name},
			Version:    defaultVersion,
			Rules:      []*policyv1.RoleRule{{Resource: placeholderResource, AllowActions: []string{placeholderAction}}},
		}}}, nil
	default:
		return nil, fmt.Errorf("unknown policy kind %q", kind)
	}
}

func policyKind(p *policyv1.Policy) string {
	switch p.GetPolicyType().(type) {
	case *policyv1.Policy_ResourcePolicy:
		return kindResource
	case *policyv1.Policy_PrincipalPolicy:
		return kindPrincipal
	case *policyv1.Policy_RolePolicy:
		return kindRole
	default:
		return ""
	}
}

func policyName(p *policyv1.Policy) string {
	switch pt := p.GetPolicyType().(type) {
	case *policyv1.Policy_ResourcePolicy:
		return pt.ResourcePolicy.GetResource()
	case *policyv1.Policy_PrincipalPolicy:
		return pt.PrincipalPolicy.GetPrincipal()
	case *policyv1.Policy_RolePolicy:
		return pt.RolePolicy.GetRole()
	default:
		return ""
	}
}

func DeleteGridRow(ctx context.Context, w *Workspace, key GridRowKey) error {
	set := w.Snapshot().Policies
	idx := -1
	for i, p := range set {
		if namer.FQN(p) == key.PolicyFQN {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("no policy with FQN %q", key.PolicyFQN)
	}

	if err := deleteRow(set[idx], key); err != nil {
		return err
	}
	if !policyHasContent(set[idx]) {
		set = append(set[:idx], set[idx+1:]...)
	}
	return w.Replace(ctx, set)
}

func deleteRow(p *policyv1.Policy, key GridRowKey) error {
	switch pt := p.GetPolicyType().(type) {
	case *policyv1.Policy_ResourcePolicy:
		return deleteResourceRow(pt.ResourcePolicy, key)
	case *policyv1.Policy_PrincipalPolicy:
		return deletePrincipalRow(pt.PrincipalPolicy, key)
	case *policyv1.Policy_RolePolicy:
		return deleteRoleRow(pt.RolePolicy, key)
	default:
		return fmt.Errorf("policy %q is not editable via the grid", key.PolicyFQN)
	}
}

func deleteResourceRow(rp *policyv1.ResourcePolicy, key GridRowKey) error {
	rule, err := indexInto(rp.GetRules(), key.RuleIndex, "rule")
	if err != nil {
		return err
	}
	_, remainder, err := carveResourceCell(rule, key)
	if err != nil {
		return err
	}
	rp.Rules = spliceRules(rp.GetRules(), key.RuleIndex, remainder)
	return nil
}

// A rectangle minus one cell may require two remainder rules.
func carveResourceCell(rule *policyv1.ResourceRule, key GridRowKey) (moved *policyv1.ResourceRule, remainder []*policyv1.ResourceRule, err error) {
	action, err := indexInto(rule.GetActions(), key.ActionIndex, "action")
	if err != nil {
		return nil, nil, err
	}

	roles, derived := rule.GetRoles(), rule.GetDerivedRoles()
	remRoles, remDerived := roles, derived
	var movedRoles, movedDerived []string
	if key.DerivedRoleIndex >= 0 {
		dr, err := indexInto(derived, key.DerivedRoleIndex, "derived role")
		if err != nil {
			return nil, nil, err
		}
		remDerived, movedDerived = removeValue(derived, dr), []string{dr}
	} else {
		role, err := indexInto(roles, key.RoleIndex, "role")
		if err != nil {
			return nil, nil, err
		}
		remRoles, movedRoles = removeValue(roles, role), []string{role}
	}
	remActions := removeValue(rule.GetActions(), action)

	moved = resourceRuleWith(rule, []string{action}, movedRoles, movedDerived)
	if len(remRoles)+len(remDerived) > 0 {
		remainder = append(remainder, resourceRuleWith(rule, []string{action}, remRoles, remDerived))
	}
	if len(remActions) > 0 {
		remainder = append(remainder, resourceRuleWith(rule, remActions, roles, derived))
	}
	return moved, remainder, nil
}

func spliceRules(rules []*policyv1.ResourceRule, i int, repl []*policyv1.ResourceRule) []*policyv1.ResourceRule {
	out := make([]*policyv1.ResourceRule, 0, len(rules)-1+len(repl))
	out = append(out, rules[:i]...)
	out = append(out, repl...)
	out = append(out, rules[i+1:]...)
	return out
}

func resourceRuleWith(src *policyv1.ResourceRule, actions, roles, derived []string) *policyv1.ResourceRule {
	r := proto.Clone(src).(*policyv1.ResourceRule) //nolint:forcetypeassert
	r.Actions, r.Roles, r.DerivedRoles, r.Name = actions, roles, derived, ""
	return r
}

func deletePrincipalRow(pp *policyv1.PrincipalPolicy, key GridRowKey) error {
	rule, err := indexInto(pp.GetRules(), key.RuleIndex, "rule")
	if err != nil {
		return err
	}
	if key.ActionIndex < 0 || key.ActionIndex >= len(rule.Actions) {
		return fmt.Errorf("action index %d out of range [0,%d)", key.ActionIndex, len(rule.Actions))
	}
	rule.Actions = append(rule.Actions[:key.ActionIndex], rule.Actions[key.ActionIndex+1:]...)
	if len(rule.Actions) == 0 {
		pp.Rules = append(pp.Rules[:key.RuleIndex], pp.Rules[key.RuleIndex+1:]...)
	}
	return nil
}

func deleteRoleRow(rp *policyv1.RolePolicy, key GridRowKey) error {
	rule, err := indexInto(rp.GetRules(), key.RuleIndex, "rule")
	if err != nil {
		return err
	}
	if key.ActionIndex < 0 || key.ActionIndex >= len(rule.AllowActions) {
		return fmt.Errorf("allow action index %d out of range [0,%d)", key.ActionIndex, len(rule.AllowActions))
	}
	rule.AllowActions = append(rule.AllowActions[:key.ActionIndex], rule.AllowActions[key.ActionIndex+1:]...)
	if len(rule.AllowActions) == 0 {
		rp.Rules = append(rp.Rules[:key.RuleIndex], rp.Rules[key.RuleIndex+1:]...)
	}
	return nil
}

func patchResourcePolicy(rp *policyv1.ResourcePolicy, key GridRowKey, patch GridPatch) error {
	rule, err := indexInto(rp.GetRules(), key.RuleIndex, "rule")
	if err != nil {
		return err
	}
	if patch.Action != nil {
		if err := setAt(rule.Actions, key.ActionIndex, *patch.Action, "action"); err != nil {
			return err
		}
	}
	if patch.Role != nil {
		if err := setAt(rule.Roles, key.RoleIndex, *patch.Role, "role"); err != nil {
			return err
		}
	}
	if patch.DerivedRole != nil {
		if err := setAt(rule.DerivedRoles, key.DerivedRoleIndex, *patch.DerivedRole, "derived role"); err != nil {
			return err
		}
	}
	if patch.Effect != nil {
		effect, err := parseEffect(*patch.Effect)
		if err != nil {
			return err
		}
		rule.Effect = effect
	}
	if patch.Condition != nil {
		rule.Condition = buildCondition(*patch.Condition)
	}
	return nil
}

func patchPrincipalPolicy(pp *policyv1.PrincipalPolicy, key GridRowKey, patch GridPatch) error {
	rule, err := indexInto(pp.GetRules(), key.RuleIndex, "rule")
	if err != nil {
		return err
	}
	if patch.Resource != nil {
		rule.Resource = *patch.Resource
	}
	action, err := indexInto(rule.GetActions(), key.ActionIndex, "action")
	if err != nil {
		return err
	}
	if patch.Action != nil {
		action.Action = *patch.Action
	}
	if patch.Effect != nil {
		effect, err := parseEffect(*patch.Effect)
		if err != nil {
			return err
		}
		action.Effect = effect
	}
	if patch.Condition != nil {
		action.Condition = buildCondition(*patch.Condition)
	}
	return nil
}

func patchRolePolicy(rp *policyv1.RolePolicy, key GridRowKey, patch GridPatch) error {
	rule, err := indexInto(rp.GetRules(), key.RuleIndex, "rule")
	if err != nil {
		return err
	}
	if patch.Resource != nil {
		rule.Resource = *patch.Resource
	}
	if patch.Action != nil {
		if err := setAt(rule.AllowActions, key.ActionIndex, *patch.Action, "allow action"); err != nil {
			return err
		}
	}
	if patch.Condition != nil {
		rule.Condition = buildCondition(*patch.Condition)
	}
	return nil
}

func findPolicy(set []*policyv1.Policy, fqn string) *policyv1.Policy {
	for _, p := range set {
		if namer.FQN(p) == fqn {
			return p
		}
	}
	return nil
}

func indexInto[T any](s []T, i int, what string) (T, error) {
	if i < 0 || i >= len(s) {
		var zero T
		return zero, fmt.Errorf("%s index %d out of range [0,%d)", what, i, len(s))
	}
	return s[i], nil
}

func setAt(s []string, i int, v, what string) error {
	if i < 0 || i >= len(s) {
		return fmt.Errorf("%s index %d out of range [0,%d)", what, i, len(s))
	}
	s[i] = v
	return nil
}

func removeValue(s []string, v string) []string {
	out := make([]string, 0, len(s))
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func parseEffect(s string) (effectv1.Effect, error) {
	switch s {
	case "EFFECT_ALLOW", "ALLOW", "allow":
		return effectv1.Effect_EFFECT_ALLOW, nil
	case "EFFECT_DENY", "DENY", "deny":
		return effectv1.Effect_EFFECT_DENY, nil
	default:
		return effectv1.Effect_EFFECT_UNSPECIFIED, fmt.Errorf("invalid effect %q", s)
	}
}

func buildCondition(expr string) *policyv1.Condition {
	if expr == "" {
		return nil
	}
	return &policyv1.Condition{
		Condition: &policyv1.Condition_Match{
			Match: &policyv1.Match{Op: &policyv1.Match_Expr{Expr: expr}},
		},
	}
}

func conditionText(c *policyv1.Condition) string {
	m := c.GetMatch()
	if m == nil {
		return ""
	}
	if expr := m.GetExpr(); expr != "" {
		return expr
	}
	return "<matcher>"
}

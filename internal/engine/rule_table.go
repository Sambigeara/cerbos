// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	storeReloadTimeout = 5 * time.Second
	storeFetchTimeout  = 2 * time.Second
)

type RuleTable struct {
	log                      *zap.SugaredLogger
	rules                    []*RuleTableRow
	policyLoader             PolicyLoader
	schemas                  map[string]*policyv1.Schemas
	policyDerivedRoles       map[string]map[string]*wrappedRunnableDerivedRole
	scopeMap                 map[string]struct{}
	scopeScopePermissions    map[string]policyv1.ScopePermissions
	parentRoles              map[string][]string
	parentRoleAncestorsCache map[string][]string
	mu                       sync.RWMutex
}

type wrappedRunnableDerivedRole struct {
	*runtimev1.RunnableDerivedRole
	constants map[string]any
}

type RuleTableRow struct {
	*runtimev1.RuleTable_RuleRow
	params        *RuleTableRowParams
	evaluationKey string
}

type RuleTableRowParams struct {
	key       string
	constants map[string]any // conditions can be converted to Go native types at build time
	variables []*runtimev1.Variable
}

func NewRuleTable() *RuleTable {
	return &RuleTable{
		log:                      zap.S().Named("ruletable"),
		schemas:                  make(map[string]*policyv1.Schemas),
		policyDerivedRoles:       make(map[string]map[string]*wrappedRunnableDerivedRole),
		scopeMap:                 make(map[string]struct{}),
		scopeScopePermissions:    make(map[string]policyv1.ScopePermissions),
		parentRoles:              make(map[string][]string),
		parentRoleAncestorsCache: make(map[string][]string),
	}
}

func (rt *RuleTable) WithPolicyLoader(policyLoader PolicyLoader) *RuleTable {
	rt.policyLoader = policyLoader
	return rt
}

func (rt *RuleTable) LoadPolicies(rps []*runtimev1.RunnablePolicySet) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for _, rp := range rps {
		rt.addPolicy(rp)
	}
}

func (rt *RuleTable) addPolicy(rps *runtimev1.RunnablePolicySet) {
	switch rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		rt.addResourcePolicy(rps.GetResourcePolicy())
	case *runtimev1.RunnablePolicySet_RolePolicy:
		rt.addRolePolicy(rps.GetRolePolicy())
	}
}

func (rt *RuleTable) addResourcePolicy(rrps *runtimev1.RunnableResourcePolicySet) {
	sanitizedResource := namer.SanitizedResource(rrps.Meta.Resource)

	meta := &runtimev1.RuleTable_Metadata{
		Fqn:              rrps.Meta.Fqn,
		Name:             &runtimev1.RuleTable_Metadata_Resource{Resource: sanitizedResource},
		Version:          rrps.Meta.Version,
		SourceAttributes: rrps.Meta.SourceAttributes,
		Annotations:      rrps.Meta.Annotations,
	}

	rt.schemas[rrps.Meta.Fqn] = rrps.Schemas

	for _, p := range rrps.GetPolicies() {
		scopeFqn := namer.ResourcePolicyFQN(rrps.Meta.Resource, rrps.Meta.Version, p.Scope)
		wrapped := make(map[string]*wrappedRunnableDerivedRole)
		for n, dr := range p.DerivedRoles {
			wrapped[n] = &wrappedRunnableDerivedRole{
				RunnableDerivedRole: dr,
				constants:           (&structpb.Struct{Fields: dr.Constants}).AsMap(),
			}
		}
		rt.policyDerivedRoles[scopeFqn] = wrapped

		rt.scopeMap[p.Scope] = struct{}{}

		policyParameters := &RuleTableRowParams{
			key:       namer.ResourcePolicyFQN(sanitizedResource, rrps.Meta.Version, p.Scope),
			variables: p.OrderedVariables,
			constants: (&structpb.Struct{Fields: p.Constants}).AsMap(),
		}

		scopePermissions := p.ScopePermissions
		if scopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
			scopePermissions = policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT
		}
		rt.scopeScopePermissions[p.Scope] = scopePermissions

		for _, rule := range p.Rules {
			emitOutput := rule.EmitOutput
			if emitOutput == nil && rule.Output != nil {
				emitOutput = &runtimev1.Output{
					When: &runtimev1.Output_When{
						RuleActivated: rule.Output,
					},
				}
			}

			ruleFqn := namer.RuleFQN(meta, p.Scope, rule.Name)
			evaluationKey := fmt.Sprintf("%s#%s", policyParameters.key, ruleFqn)
			for a := range rule.Actions {
				for r := range rule.Roles {
					rt.rules = append(rt.rules, &RuleTableRow{
						RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
							OriginFqn:        rrps.Meta.Fqn,
							Resource:         sanitizedResource,
							Role:             r,
							Action:           a,
							Condition:        rule.Condition,
							Effect:           rule.Effect,
							Scope:            p.Scope,
							ScopePermissions: scopePermissions,
							Version:          rrps.Meta.Version,
							EmitOutput:       emitOutput,
							Name:             rule.Name,
							Meta:             meta,
						},
						params:        policyParameters,
						evaluationKey: evaluationKey,
					})
				}

				// merge derived roles as roles with added conditions
				for dr := range rule.DerivedRoles {
					if rdr, ok := p.DerivedRoles[dr]; ok {
						mergedVariables := make([]*runtimev1.Variable, len(p.OrderedVariables)+len(rdr.OrderedVariables))
						copy(mergedVariables, p.OrderedVariables)
						copy(mergedVariables[len(p.OrderedVariables):], rdr.OrderedVariables)

						mergedConstants := maps.Clone(p.Constants)
						for k, c := range rdr.Constants {
							mergedConstants[k] = c
						}

						mergedParameters := &RuleTableRowParams{
							key:       fmt.Sprintf("%s:%s", policyParameters.key, namer.DerivedRolesFQN(rdr.Name)),
							variables: mergedVariables,
							constants: (&structpb.Struct{Fields: mergedConstants}).AsMap(),
						}

						cond := rule.Condition
						if rdr.Condition != nil {
							if cond == nil {
								cond = rdr.Condition
							} else {
								cond = &runtimev1.Condition{
									Op: &runtimev1.Condition_All{
										All: &runtimev1.Condition_ExprList{
											Expr: []*runtimev1.Condition{cond, rdr.Condition},
										},
									},
								}
							}
						}

						evaluationKey := fmt.Sprintf("%s#%s", mergedParameters.key, ruleFqn)
						for pr := range rdr.ParentRoles {
							rt.rules = append(rt.rules, &RuleTableRow{
								RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
									OriginFqn:         rrps.Meta.Fqn,
									Resource:          sanitizedResource,
									Role:              pr,
									Action:            a,
									Condition:         cond,
									Effect:            rule.Effect,
									Scope:             p.Scope,
									ScopePermissions:  scopePermissions,
									Version:           rrps.Meta.Version,
									OriginDerivedRole: dr,
									EmitOutput:        emitOutput,
									Name:              rule.Name,
									Meta:              meta,
								},
								params:        mergedParameters,
								evaluationKey: evaluationKey,
							})
						}
					}
				}
			}
		}
	}
}

func (rt *RuleTable) addRolePolicy(p *runtimev1.RunnableRolePolicySet) {
	rt.scopeMap[p.Scope] = struct{}{}
	rt.scopeScopePermissions[p.Scope] = p.ScopePermissions

	version := "default"
	meta := &runtimev1.RuleTable_Metadata{
		Fqn:              p.Meta.Fqn,
		Name:             &runtimev1.RuleTable_Metadata_Role{Role: p.Role},
		Version:          version,
		SourceAttributes: p.Meta.SourceAttributes,
		Annotations:      p.Meta.Annotations,
	}
	for resource, rl := range p.Resources {
		for idx, rule := range rl.Rules {
			evaluationKey := fmt.Sprintf("%s#%s_rule-%03d", namer.PolicyKeyFromFQN(namer.RolePolicyFQN(p.Role, p.Scope)), p.Role, idx)
			for a := range rule.Actions {
				rt.rules = append(rt.rules, &RuleTableRow{
					RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
						OriginFqn:        p.Meta.Fqn,
						Role:             p.Role,
						Resource:         resource,
						Action:           a,
						Condition:        rule.Condition,
						Effect:           effectv1.Effect_EFFECT_ALLOW,
						Scope:            p.Scope,
						ScopePermissions: p.ScopePermissions,
						Version:          version,
						Meta:             meta,
					},
					evaluationKey: evaluationKey,
				})
			}
		}
	}

	rt.parentRoles[p.Role] = p.ParentRoles
}

func (rt *RuleTable) deletePolicy(rps *runtimev1.RunnablePolicySet) {
	// TODO(saml) rebuilding/reassigning the whole row slice on each delete is hugely inefficient.
	// Perhaps we could mark as `deleted` and periodically purge the deleted rows.
	// However, it's unlikely this bespoke table implementation will be around long enough to worry about this.

	rt.mu.Lock()
	defer rt.mu.Unlock()

	deletedFqn := rps.Fqn
	scopeSet := make(map[string]struct{})

	newRules := []*RuleTableRow{}
	for _, r := range rt.rules {
		if r.OriginFqn != deletedFqn {
			newRules = append(newRules, r)
			scopeSet[r.Scope] = struct{}{}
		}
	}
	rt.rules = newRules

	delete(rt.schemas, deletedFqn)

	var scope string
	switch rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		rp := rps.GetResourcePolicy()
		scope = rp.Policies[0].Scope
	case *runtimev1.RunnablePolicySet_RolePolicy:
		rlp := rps.GetRolePolicy()
		scope = rlp.Scope

		delete(rt.parentRoles, rlp.Role)
		delete(rt.parentRoleAncestorsCache, rlp.Role)
	}

	if _, ok := scopeSet[scope]; !ok {
		delete(rt.scopeMap, scope)
		delete(rt.scopeScopePermissions, scope)
	}
}

func (rt *RuleTable) purge() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.rules = []*RuleTableRow{}
	rt.parentRoles = make(map[string][]string)
	rt.schemas = make(map[string]*policyv1.Schemas)

	rt.scopeMap = make(map[string]struct{})
	rt.parentRoleAncestorsCache = make(map[string][]string)
}

func (rt *RuleTable) GetAllScopes(scope, resource, version string) ([]string, string, string) {
	var firstPolicyKey, firstFqn string
	var scopes []string
	if rt.ScopeExists(scope) {
		firstFqn = namer.ResourcePolicyFQN(resource, version, scope)
		firstPolicyKey = namer.PolicyKeyFromFQN(firstFqn)
		scopes = append(scopes, scope)
	}

	for i := len(scope) - 1; i >= 0; i-- {
		if scope[i] == '.' || i == 0 {
			partialScope := scope[:i]
			if rt.ScopeExists(partialScope) {
				scopes = append(scopes, partialScope)
				if firstPolicyKey == "" {
					firstFqn = namer.ResourcePolicyFQN(resource, version, partialScope)
					firstPolicyKey = namer.PolicyKeyFromFQN(firstFqn)
				}
			}
		}
	}

	return scopes, firstPolicyKey, firstFqn
}

func (rt *RuleTable) ScanRows(version, resource string, scopes, roles, actions []string) *RuleSet {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	res := &RuleSet{
		scopeIndex: make(map[string][]*RuleTableRow),
	}

	scopeSet := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		scopeSet[s] = struct{}{}
	}

	parentRoles := rt.getParentRoles(roles)

	for _, row := range rt.rules {
		if version != "" && version != row.Version {
			continue
		}

		if len(scopes) > 0 {
			if _, ok := scopeSet[row.Scope]; !ok {
				continue
			}
		}

		if resource != "" && !util.MatchesGlob(row.Resource, resource) {
			continue
		}

		if len(actions) > 0 && len(util.FilterGlob(row.Action, actions)) == 0 {
			continue
		}

		if len(roles) > 0 && len(util.FilterGlob(row.Role, roles)) == 0 {
			// if the row matched on an assumed parent role, update the role in the row to an arbitrary base role
			// so that we don't need to retrieve parent roles each time we query on the same set of data.
			if len(util.FilterGlob(row.Role, parentRoles)) > 0 {
				row.Role = roles[0]
			} else {
				continue
			}
		}

		res.addMatchingRow(row)
	}

	return res
}

func (rt *RuleTable) getParentRoles(roles []string) []string {
	// recursively collect all parent roles, caching the flat list on the very first traversal for
	// each role within the ruletable
	parentRoles := make([]string, len(roles))
	copy(parentRoles, roles)
	for _, role := range roles {
		var roleParents []string
		if c, ok := rt.parentRoleAncestorsCache[role]; ok {
			roleParents = c
		} else {
			visited := make(map[string]struct{})
			roleParentsSet := make(map[string]struct{})
			rt.collectParentRoles(role, roleParentsSet, visited)
			roleParents = make([]string, 0, len(roleParentsSet))
			for r := range roleParentsSet {
				roleParents = append(roleParents, r)
			}
			rt.parentRoleAncestorsCache[role] = roleParents
		}
		parentRoles = append(parentRoles, roleParents...)
	}
	return parentRoles
}

func (rt *RuleTable) collectParentRoles(role string, parentRoleSet map[string]struct{}, visited map[string]struct{}) {
	if _, seen := visited[role]; seen {
		return
	}
	visited[role] = struct{}{}

	if prs, ok := rt.parentRoles[role]; ok {
		for _, pr := range prs {
			parentRoleSet[pr] = struct{}{}
			rt.collectParentRoles(pr, parentRoleSet, visited)
		}
	}
}

func (rt *RuleTable) ScopeExists(scope string) bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	_, ok := rt.scopeMap[scope]
	return ok
}

func (rt *RuleTable) GetScopeScopePermissions(scope string) policyv1.ScopePermissions {
	return rt.scopeScopePermissions[scope]
}

func (rt *RuleTable) GetSchema(fqn string) *policyv1.Schemas {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if s, ok := rt.schemas[fqn]; ok {
		return s
	}

	return nil
}

func (rt *RuleTable) Filter(rrs *RuleSet, scopes, roles, actions []string) *RuleSet {
	// TODO(saml) avoid repeatedly creating and returning new (reduced) slices, via a per-row boolean or perhaps a linked list
	// to infer whether or not it's in a result set? Idea requires refining, but in essence, we'd use a single array under the
	// hood which would be much more efficient.
	res := &RuleSet{
		scopeIndex: make(map[string][]*RuleTableRow),
	}

	parentRoles := rt.getParentRoles(roles)

	if len(scopes) == 0 {
		scopes = make([]string, 0, len(rrs.scopeIndex))
		for s := range rrs.scopeIndex {
			scopes = append(scopes, s)
		}
	}

	for _, s := range scopes {
		if sMap, ok := rrs.scopeIndex[s]; ok {
			for _, row := range sMap {
				if len(actions) == 0 || len(util.FilterGlob(row.Action, actions)) > 0 {
					if len(roles) == 0 || len(util.FilterGlob(row.Role, roles)) > 0 {
						res.addMatchingRow(row)
					} else if len(util.FilterGlob(row.Role, parentRoles)) > 0 {
						row.Role = roles[0]
						res.addMatchingRow(row)
					}
				}
			}
		}
	}

	return res
}

func (rt *RuleTable) SubscriberID() string {
	return "engine.RuleTable"
}

func (rt *RuleTable) OnStorageEvent(events ...storage.Event) {
	for _, evt := range events {
		switch evt.Kind {
		case storage.EventReload:
			rt.log.Info("Reloading ruletable")
			rt.triggerReload()
		case storage.EventAddOrUpdatePolicy, storage.EventDeleteOrDisablePolicy:
			rt.log.Debugw("Processing storage event", "event", evt)
			if err := rt.processPolicyEvent(evt); err != nil {
				rt.log.Warnw("Error while processing storage event", "event", evt, "error", err)
			}
		default:
			rt.log.Debugw("Ignoring storage event", "event", evt)
		}
	}
}

func (rt *RuleTable) triggerReload() error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), storeReloadTimeout)
	defer cancelFunc()

	rpss, err := rt.policyLoader.GetAll(ctx)
	if err != nil {
		return err
	}

	rt.purge()
	rt.LoadPolicies(rpss)

	return nil
}

func (rt *RuleTable) processPolicyEvent(ev storage.Event) error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), storeFetchTimeout)
	defer cancelFunc()

	rps, err := rt.policyLoader.GetFirstMatch(ctx, []namer.ModuleID{ev.PolicyID})
	if err != nil {
		return err
	}

	rt.deletePolicy(rps)

	if ev.Kind == storage.EventAddOrUpdatePolicy {
		rt.addPolicy(rps)
	}

	return nil
}

type RuleSet struct {
	rows       []*RuleTableRow
	scopeIndex map[string][]*RuleTableRow
}

func (rrs *RuleSet) addMatchingRow(row *RuleTableRow) {
	rrs.rows = append(rrs.rows, row)
	rrs.scopeIndex[row.Scope] = append(rrs.scopeIndex[row.Scope], row)
}

func (rrs *RuleSet) GetRows() []*RuleTableRow {
	return rrs.rows
}

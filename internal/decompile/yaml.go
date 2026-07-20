// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package decompile

import (
	"bytes"
	"io"
	"sort"

	"gopkg.in/yaml.v3"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/policy"
)

const yamlIndent = 2

var (
	topOrder             = []string{"apiVersion", "description", "disabled", "metadata", "resourcePolicy", "principalPolicy", "rolePolicy", "derivedRoles", "exportVariables", "exportConstants"}
	resourceBodyOrder    = []string{"resource", "version", "scope", "scopePermissions", "importDerivedRoles", "variables", "constants", "schemas", "rules"}
	principalBodyOrder   = []string{"principal", "version", "scope", "scopePermissions", "variables", "constants", "rules"}
	roleBodyOrder        = []string{"role", "version", "scope", "scopePermissions", "variables", "constants", "parentRoles", "rules"}
	resourceRuleOrder    = []string{"actions", "roles", "derivedRoles", "effect", "condition", "name", "output"}
	principalRuleOrder   = []string{"resource", "actions"}
	principalActionOrder = []string{"action", "effect", "condition", "name", "output"}
	roleRuleOrder        = []string{"resource", "allowActions", "condition", "name", "output"}
	derivedRolesOrder    = []string{"name", "variables", "constants", "definitions"}
	roleDefOrder         = []string{"name", "parentRoles", "condition"}
	varsOrder            = []string{"import", "local"}
)

func WriteYAML(w io.Writer, p *policyv1.Policy) error {
	var buf bytes.Buffer
	if err := policy.WritePolicy(&buf, p); err != nil {
		return err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(buf.Bytes(), &doc); err != nil {
		return err
	}
	reorderDocument(&doc)

	enc := yaml.NewEncoder(w)
	enc.SetIndent(yamlIndent)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	return enc.Close()
}

func reorderDocument(doc *yaml.Node) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return
	}
	root := doc.Content[0]
	reorderKeys(root, topOrder)

	if body := child(root, "resourcePolicy"); body != nil {
		reorderKeys(body, resourceBodyOrder)
		for _, rule := range seqItems(child(body, "rules")) {
			reorderKeys(rule, resourceRuleOrder)
		}
		reorderVars(body)
	}
	if body := child(root, "principalPolicy"); body != nil {
		reorderKeys(body, principalBodyOrder)
		for _, rule := range seqItems(child(body, "rules")) {
			reorderKeys(rule, principalRuleOrder)
			for _, action := range seqItems(child(rule, "actions")) {
				reorderKeys(action, principalActionOrder)
			}
		}
		reorderVars(body)
	}
	if body := child(root, "rolePolicy"); body != nil {
		reorderKeys(body, roleBodyOrder)
		for _, rule := range seqItems(child(body, "rules")) {
			reorderKeys(rule, roleRuleOrder)
		}
		reorderVars(body)
	}
	if body := child(root, "derivedRoles"); body != nil {
		reorderKeys(body, derivedRolesOrder)
		for _, def := range seqItems(child(body, "definitions")) {
			reorderKeys(def, roleDefOrder)
		}
		reorderVars(body)
	}
}

func reorderVars(body *yaml.Node) {
	reorderKeys(child(body, "variables"), varsOrder)
	reorderKeys(child(body, "constants"), varsOrder)
}

func reorderKeys(m *yaml.Node, order []string) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	rank := make(map[string]int, len(order))
	for i, k := range order {
		rank[k] = i
	}

	type pair struct{ key, val *yaml.Node }
	pairs := make([]pair, 0, len(m.Content))
	for i := 0; i+1 < len(m.Content); i += 2 {
		pairs = append(pairs, pair{m.Content[i], m.Content[i+1]})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		ri, oki := rank[pairs[i].key.Value]
		rj, okj := rank[pairs[j].key.Value]
		switch {
		case oki && okj:
			return ri < rj
		case oki != okj:
			return oki
		default:
			return pairs[i].key.Value < pairs[j].key.Value
		}
	})

	m.Content = m.Content[:0]
	for _, p := range pairs {
		m.Content = append(m.Content, p.key, p.val)
	}
}

func child(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func seqItems(n *yaml.Node) []*yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

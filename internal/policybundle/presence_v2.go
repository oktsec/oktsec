package policybundle

import (
	"encoding/json"
	"fmt"
)

// validateScalarPresenceV2 walks the RAW JSON of a policy_bundle.v2 and fails
// if any SIGNED SCALAR field is omitted or present as JSON null. It runs after
// rejectDuplicateKeys and before the typed struct is trusted, alongside the
// other canonical-form guards (strict decode, duplicate keys, container
// presence). It does NOT reserialize: it walks raw bytes into
// map[string]json.RawMessage / []json.RawMessage so it can distinguish an
// ABSENT key (missing from the map) from a PRESENT-null key (RawMessage with
// the literal bytes "null").
//
// Why this exists: a scalar omitted or set to null in the JSON decodes to Go's
// zero value before the canonical hash is recomputed, so suspended.value
// omitted would verify identically to suspended.value:false, rollback_of
// omitted identically to "", an omitted numeric identically to 0. That gives
// the contract two verifiable byte-representations for one meaning, which
// contradicts the strictness already enforced for containers (present as []/{}),
// timestamps (exact wire bytes), and decimals (strictly positive). v2 freezes
// the contract requiring every signed scalar to be explicitly present.
//
// Scope boundary: this validator handles SCALARS (strings, bools, numbers, and
// the closed-set tri-state/enum strings) AND scalar leaves inside containers -
// i.e. null ELEMENTS of signed string arrays and null VALUES of signed string
// maps. The CONTAINER's own presence (present as []/{} not null) stays with
// validateCanonicalPolicyContainersV2; this validator only refuses null at the
// scalar leaf so a null cannot decode to "" and share a hash with an explicit
// "". At a mixed boundary the two cooperate without overlap: e.g.
// tool_policies.by_tool is a MAP (container rule for the map, scalar rule for
// each entry's max_amount); governance.agents is an ARRAY (container rule for
// the array, scalar rule for each agent's suspended.value);
// gateway.tools_allowed is a string array (container rule for [], this rule for
// each element being non-null).
//
// The walker is driven by the body's own structure: it descends fixed object
// fields, EVERY element of arrays, and EVERY value of maps, asserting the
// required scalar keys at each node. A scalar is "present" iff its key exists
// AND its value is not the JSON literal null.
func validateScalarPresenceV2(raw []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		// Structural problems are the strict decoder's concern; this guard only
		// runs after a successful typed decode, so a parse error here would be a
		// programming error rather than a bundle defect. Surface it conservatively.
		return fmt.Errorf("scalar presence: parse bundle: %s", err)
	}

	policy, err := childObject(top, "policy")
	if err != nil {
		return err
	}

	// Body-level scalars.
	if err := requireScalars("policy", policy, "policy_id", "policy_version", "mode"); err != nil {
		return err
	}

	// assignment + assignment.target.
	assignment, err := childObject(policy, "policy.assignment", "assignment")
	if err != nil {
		return err
	}
	if err := requireScalars("policy.assignment", assignment,
		"assignment_id", "issued_at", "sequence", "rollback_of"); err != nil {
		return err
	}
	target, err := childObject(assignment, "policy.assignment.target", "target")
	if err != nil {
		return err
	}
	// node_id may be "" for fleet scope (valid), but the KEY must be present.
	if err := requireScalars("policy.assignment.target", target, "scope", "node_id"); err != nil {
		return err
	}

	// Top-level dimension modes (the scalar in each dimension; the dimension's
	// containers are validated by validateCanonicalPolicyContainersV2).
	if err := requireDimMode(policy, "policy.rules", "rules"); err != nil {
		return err
	}
	if err := requireDimMode(policy, "policy.gateway", "gateway"); err != nil {
		return err
	}
	if err := requireDimMode(policy, "policy.egress", "egress"); err != nil {
		return err
	}

	// Top-level signed string-array containers: reject null ELEMENTS (the empty
	// container itself is the container validator's concern). A null element
	// decodes to "" and would otherwise share a hash with an explicit "".
	gateway, err := childObject(policy, "policy.gateway", "gateway")
	if err != nil {
		return err
	}
	egress, err := childObject(policy, "policy.egress", "egress")
	if err != nil {
		return err
	}
	rules, err := childObject(policy, "policy.rules", "rules")
	if err != nil {
		return err
	}
	for _, sa := range []struct {
		parent    map[string]json.RawMessage
		path, key string
	}{
		{rules, "policy.rules.enabled", "enabled"},
		{rules, "policy.rules.disabled", "disabled"},
		{gateway, "policy.gateway.tools_allowed", "tools_allowed"},
		{gateway, "policy.gateway.tools_denied", "tools_denied"},
		{egress, "policy.egress.domains_allowed", "domains_allowed"},
		{egress, "policy.egress.domains_denied", "domains_denied"},
	} {
		if err := rejectNullStringArrayElems(sa.parent, sa.path, sa.key); err != nil {
			return err
		}
	}

	// rules.overrides is a MAP (container rule) whose every entry carries a
	// scalar "action".
	if overrides, present, err := optionalChildMap(rules, "policy.rules.overrides", "overrides"); err != nil {
		return err
	} else if present {
		for id, ovRaw := range overrides {
			ov, err := asObject(fmt.Sprintf("policy.rules.overrides[%q]", id), ovRaw)
			if err != nil {
				return err
			}
			if err := requireScalars(fmt.Sprintf("policy.rules.overrides[%q]", id), ov, "action"); err != nil {
				return err
			}
		}
	}

	// redaction + metadata.
	redaction, err := childObject(policy, "policy.redaction", "redaction")
	if err != nil {
		return err
	}
	if err := requireScalars("policy.redaction", redaction, "mode", "level"); err != nil {
		return err
	}
	metadata, err := childObject(policy, "policy.metadata", "metadata")
	if err != nil {
		return err
	}
	if err := requireScalars("policy.metadata", metadata, "created_at", "created_by", "reason"); err != nil {
		return err
	}

	// governance.server + governance.agents[*].
	governance, err := childObject(policy, "policy.governance", "governance")
	if err != nil {
		return err
	}
	server, err := childObject(governance, "policy.governance.server", "server")
	if err != nil {
		return err
	}
	if err := requireScalars("policy.governance.server", server,
		"mode", "require_intent", "rate_limit_max", "rate_limit_window_s"); err != nil {
		return err
	}

	agents, present, err := optionalChildArray(governance, "policy.governance.agents", "agents")
	if err != nil {
		return err
	}
	if present {
		for i, agentRaw := range agents {
			if err := validateAgentScalarPresenceV2(i, agentRaw); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateAgentScalarPresenceV2 asserts every signed scalar on one
// governance.agents[i] entry is present and non-null, descending into its
// map-keyed (tool_policies.by_tool, tool_constraints[].parameters) and
// array-element (tool_constraints.items, tool_chain_rules.items) sub-surfaces.
func validateAgentScalarPresenceV2(i int, agentRaw json.RawMessage) error {
	p := fmt.Sprintf("policy.governance.agents[%d]", i)
	agent, err := asObject(p, agentRaw)
	if err != nil {
		return err
	}

	// selector.name (scalar) + selector.labels (a string-VALUE map: the map's
	// own presence is the container validator's concern, but a null VALUE decodes
	// to "" and would share a hash with an explicit "", so null values are
	// rejected here).
	selector, err := childObject(agent, p+".selector", "selector")
	if err != nil {
		return err
	}
	if err := requireScalars(p+".selector", selector, "name"); err != nil {
		return err
	}
	if err := rejectNullStringMapValues(selector, p+".selector.labels", "labels"); err != nil {
		return err
	}

	// acls: mode scalar + two string-array containers (null elements rejected).
	acls, err := childObject(agent, p+".acls", "acls")
	if err != nil {
		return err
	}
	if err := requireScalars(p+".acls", acls, "mode"); err != nil {
		return err
	}
	if err := rejectNullStringArrayElems(acls, p+".acls.allowed_recipients", "allowed_recipients"); err != nil {
		return err
	}
	if err := rejectNullStringArrayElems(acls, p+".acls.blocked_recipients", "blocked_recipients"); err != nil {
		return err
	}

	// allowed_tools / blocked_content: mode scalar + a "values" string array.
	for _, dim := range []string{"allowed_tools", "blocked_content"} {
		d, err := childObject(agent, p+"."+dim, dim)
		if err != nil {
			return err
		}
		if err := requireScalars(p+"."+dim, d, "mode"); err != nil {
			return err
		}
		if err := rejectNullStringArrayElems(d, p+"."+dim+".values", "values"); err != nil {
			return err
		}
	}

	// scan_profile: mode + value (closed-set string).
	scanProfile, err := childObject(agent, p+".scan_profile", "scan_profile")
	if err != nil {
		return err
	}
	if err := requireScalars(p+".scan_profile", scanProfile, "mode", "value"); err != nil {
		return err
	}

	// suspended: mode + value (bool; false valid only if present).
	suspended, err := childObject(agent, p+".suspended", "suspended")
	if err != nil {
		return err
	}
	if err := requireScalars(p+".suspended", suspended, "mode", "value"); err != nil {
		return err
	}

	// tool_policies: mode scalar + by_tool MAP whose every entry carries scalar
	// limits. max_amount/daily_limit/require_approval_above are decimal strings:
	// "" is a valid (explicit unset) VALUE, but the KEY must be present.
	tp, err := childObject(agent, p+".tool_policies", "tool_policies")
	if err != nil {
		return err
	}
	if err := requireScalars(p+".tool_policies", tp, "mode"); err != nil {
		return err
	}
	if byTool, present, err := optionalChildMap(tp, p+".tool_policies.by_tool", "by_tool"); err != nil {
		return err
	} else if present {
		for tool, tpRaw := range byTool {
			tpName := fmt.Sprintf("%s.tool_policies.by_tool[%q]", p, tool)
			tpObj, err := asObject(tpName, tpRaw)
			if err != nil {
				return err
			}
			if err := requireScalars(tpName, tpObj,
				"max_amount", "daily_limit", "require_approval_above", "rate_limit"); err != nil {
				return err
			}
		}
	}

	// tool_constraints: mode scalar + items ARRAY; each item carries scalars and
	// a parameters MAP whose every entry carries a scalar max_length.
	tc, err := childObject(agent, p+".tool_constraints", "tool_constraints")
	if err != nil {
		return err
	}
	if err := requireScalars(p+".tool_constraints", tc, "mode"); err != nil {
		return err
	}
	if items, present, err := optionalChildArray(tc, p+".tool_constraints.items", "items"); err != nil {
		return err
	} else if present {
		for j, itemRaw := range items {
			cp := fmt.Sprintf("%s.tool_constraints.items[%d]", p, j)
			item, err := asObject(cp, itemRaw)
			if err != nil {
				return err
			}
			if err := requireScalars(cp, item, "tool", "max_response_bytes", "cooldown_secs"); err != nil {
				return err
			}
			if params, present, err := optionalChildMap(item, cp+".parameters", "parameters"); err != nil {
				return err
			} else if present {
				for name, pcRaw := range params {
					pcName := fmt.Sprintf("%s.parameters[%q]", cp, name)
					pc, err := asObject(pcName, pcRaw)
					if err != nil {
						return err
					}
					if err := requireScalars(pcName, pc, "max_length"); err != nil {
						return err
					}
					if err := rejectNullStringArrayElems(pc, pcName+".allowed_patterns", "allowed_patterns"); err != nil {
						return err
					}
					if err := rejectNullStringArrayElems(pc, pcName+".blocked_patterns", "blocked_patterns"); err != nil {
						return err
					}
				}
			}
		}
	}

	// tool_chain_rules: mode scalar + items ARRAY; each item carries scalar
	// "if" and "cooldown_secs" plus a "then" string array (null elements rejected).
	tcr, err := childObject(agent, p+".tool_chain_rules", "tool_chain_rules")
	if err != nil {
		return err
	}
	if err := requireScalars(p+".tool_chain_rules", tcr, "mode"); err != nil {
		return err
	}
	if items, present, err := optionalChildArray(tcr, p+".tool_chain_rules.items", "items"); err != nil {
		return err
	} else if present {
		for j, itemRaw := range items {
			rp := fmt.Sprintf("%s.tool_chain_rules.items[%d]", p, j)
			item, err := asObject(rp, itemRaw)
			if err != nil {
				return err
			}
			if err := requireScalars(rp, item, "if", "cooldown_secs"); err != nil {
				return err
			}
			if err := rejectNullStringArrayElems(item, rp+".then", "then"); err != nil {
				return err
			}
		}
	}

	// egress: scalars (mode, scope, tri-state strings, integer counts) plus the
	// string-array containers (allowed_domains, blocked_domains, blocked_categories,
	// integrations) and the string-array MAP (tool_restrictions). The containers'
	// own presence is the container validator's concern; here we reject null
	// string ELEMENTS / values so they cannot collide with an explicit "".
	egress, err := childObject(agent, p+".egress", "egress")
	if err != nil {
		return err
	}
	if err := requireScalars(p+".egress", egress,
		"mode", "scope", "scan_requests", "scan_responses", "rate_limit", "rate_window"); err != nil {
		return err
	}
	for _, sa := range []struct{ path, key string }{
		{p + ".egress.allowed_domains", "allowed_domains"},
		{p + ".egress.blocked_domains", "blocked_domains"},
		{p + ".egress.blocked_categories", "blocked_categories"},
		{p + ".egress.integrations", "integrations"},
	} {
		if err := rejectNullStringArrayElems(egress, sa.path, sa.key); err != nil {
			return err
		}
	}
	if err := rejectNullStringMapOfArrays(egress, p+".egress.tool_restrictions", "tool_restrictions"); err != nil {
		return err
	}

	return nil
}

// requireDimMode asserts a dimension object exists and carries a present,
// non-null scalar "mode". It is the common case for the many wrapper dimensions
// whose only scalar is the mode.
func requireDimMode(parent map[string]json.RawMessage, path, key string) error {
	dim, err := childObject(parent, path, key)
	if err != nil {
		return err
	}
	return requireScalars(path, dim, "mode")
}

// requireScalars asserts each named key exists in obj AND is not JSON null.
// "present" iff the key is in the map and its raw value is not the literal
// bytes "null" (absent keys are simply missing from the map after Unmarshal).
func requireScalars(path string, obj map[string]json.RawMessage, keys ...string) error {
	for _, k := range keys {
		v, ok := obj[k]
		if !ok {
			return fmt.Errorf("%s.%s: required scalar field is absent or null", path, k)
		}
		if isJSONNull(v) {
			return fmt.Errorf("%s.%s: required scalar field is absent or null", path, k)
		}
	}
	return nil
}

// childObject decodes a REQUIRED child object at key. The optional name
// overrides the default path-derived name in the error. A missing, null, or
// non-object child is an error (its absence is itself a presence violation for
// the scalars it would contain). Container-typed children (arrays/maps that the
// container validator owns) are NOT decoded through here.
func childObject(parent map[string]json.RawMessage, pathOrKey string, key ...string) (map[string]json.RawMessage, error) {
	path := pathOrKey
	k := pathOrKey
	if len(key) == 1 {
		k = key[0]
	}
	v, ok := parent[k]
	if !ok || isJSONNull(v) {
		return nil, fmt.Errorf("%s: required object is absent or null", path)
	}
	return asObject(path, v)
}

// asObject decodes raw as a JSON object map. A non-object (or null) is an error.
func asObject(path string, raw json.RawMessage) (map[string]json.RawMessage, error) {
	if isJSONNull(raw) {
		return nil, fmt.Errorf("%s: required object is absent or null", path)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: not a JSON object: %s", path, err)
	}
	if m == nil {
		return nil, fmt.Errorf("%s: required object is absent or null", path)
	}
	return m, nil
}

// optionalChildMap decodes a map-typed container child if present and non-null.
// Presence/null of the container itself is the container validator's concern;
// this only walks INTO it to reach scalar leaves. Returns present=false when
// the key is absent or null so the caller skips it without error.
func optionalChildMap(parent map[string]json.RawMessage, path, key string) (map[string]json.RawMessage, bool, error) {
	v, ok := parent[key]
	if !ok || isJSONNull(v) {
		return nil, false, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(v, &m); err != nil {
		return nil, false, fmt.Errorf("%s: not a JSON object: %s", path, err)
	}
	return m, true, nil
}

// optionalChildArray decodes an array-typed container child if present and
// non-null. Same division of labor as optionalChildMap.
func optionalChildArray(parent map[string]json.RawMessage, path, key string) ([]json.RawMessage, bool, error) {
	v, ok := parent[key]
	if !ok || isJSONNull(v) {
		return nil, false, nil
	}
	var a []json.RawMessage
	if err := json.Unmarshal(v, &a); err != nil {
		return nil, false, fmt.Errorf("%s: not a JSON array: %s", path, err)
	}
	return a, true, nil
}

// rejectNullStringArrayElems rejects a JSON null ELEMENT inside a signed
// string-array container (e.g. gateway.tools_allowed, acls.allowed_recipients,
// a parameter's allowed_patterns). encoding/json decodes a null element of a
// []string to "", so a bundle signed with [""] and a wire bundle with [null]
// recompute the SAME hash and both verify - the same dual-byte-representation
// defect this PR freezes out, one level inside the container. The container's
// own presence ([] not null) stays with validateCanonicalPolicyContainersV2;
// this only refuses null ELEMENTS so every string element is explicit on the
// wire. Absent/null container itself is skipped here (container validator owns it).
func rejectNullStringArrayElems(parent map[string]json.RawMessage, path, key string) error {
	elems, present, err := optionalChildArray(parent, path, key)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	for i, e := range elems {
		if isJSONNull(e) {
			return fmt.Errorf("%s[%d]: string element must not be null", path, i)
		}
	}
	return nil
}

// rejectNullStringMapValues rejects a JSON null VALUE inside a signed map whose
// values are strings (selector.labels). Same reasoning as
// rejectNullStringArrayElems: a null value decodes to "" and would collide with
// an explicit "" on the hash. The map's own presence ({} not null) stays with
// the container validator.
func rejectNullStringMapValues(parent map[string]json.RawMessage, path, key string) error {
	m, present, err := optionalChildMap(parent, path, key)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	for k, v := range m {
		if isJSONNull(v) {
			return fmt.Errorf("%s[%q]: string value must not be null", path, k)
		}
	}
	return nil
}

// rejectNullStringMapOfArrays rejects a JSON null ELEMENT inside a map whose
// values are string arrays (egress.tool_restrictions). The map and each array's
// own presence stay with the container validator; this refuses null string
// elements so every restriction domain is explicit.
func rejectNullStringMapOfArrays(parent map[string]json.RawMessage, path, key string) error {
	m, present, err := optionalChildMap(parent, path, key)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	for k, vRaw := range m {
		if isJSONNull(vRaw) {
			// The container validator rejects a null array value; nothing to walk.
			continue
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(vRaw, &arr); err != nil {
			return fmt.Errorf("%s[%q]: not a JSON array: %s", path, k, err)
		}
		for i, e := range arr {
			if isJSONNull(e) {
				return fmt.Errorf("%s[%q][%d]: string element must not be null", path, k, i)
			}
		}
	}
	return nil
}

// isJSONNull reports whether a raw value is the JSON literal null. A present
// key whose value is null is treated identically to an absent key: a scalar
// must be explicitly present with a non-null value.
func isJSONNull(raw json.RawMessage) bool {
	return string(jsonTrimSpace(raw)) == "null"
}

// jsonTrimSpace trims the insignificant JSON whitespace bytes around a raw
// value so a null surrounded by spaces is still recognized. json.RawMessage for
// a field captures the value bytes including any surrounding whitespace the
// source had; the JSON grammar's insignificant whitespace is space, tab, CR, LF.
func jsonTrimSpace(raw json.RawMessage) []byte {
	start := 0
	for start < len(raw) && isJSONSpace(raw[start]) {
		start++
	}
	end := len(raw)
	for end > start && isJSONSpace(raw[end-1]) {
		end--
	}
	return raw[start:end]
}

func isJSONSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

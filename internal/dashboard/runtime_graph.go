package dashboard

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/oktsec/oktsec/internal/graph"
	"github.com/oktsec/oktsec/internal/runtime"
)

// runtimeGraphTopTools caps the tool-node list the dashboard
// renders. Mirrors the legacy buildGraph cap so the runtime
// path does not flood the page with rare tools.
const runtimeGraphTopTools = 5

// buildRuntimeGraph projects the Phase 3 runtime tables into a
// generic graph the dashboard can render. The graph package stays
// client-agnostic; this file is the only place that knows about
// runtime concepts (sessions, actors, hook events, lifecycle,
// stage).
//
// Two distinct booleans are returned so the caller can pick the
// right fallback policy:
//
//   - usable: true when the runtime store is wired AND has at
//     least one row (real or heartbeat) in the window. The
//     dashboard MUST trust this graph even when it is empty —
//     a heartbeat-only state legitimately renders no edges, and
//     falling back to legacy here would let an old audit row
//     resurrect a phantom node the user explicitly does not
//     want to see.
//   - false: store unavailable, query failed, OR no rows at all
//     in the window. The caller falls back to the legacy
//     audit-driven graph so brand-new installs and the existing
//     audit-only test suite keep rendering.
//
// Range filter is the same RFC3339 timestamp parseSinceRange
// produces; passing "" means "all time".
func (s *Server) buildRuntimeGraph(since string) (*graph.AgentGraph, bool) {
	store := s.runtimeStore()
	if store == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sinceTime, _ := time.Parse(time.RFC3339, since)

	events, err := store.QueryEvents(ctx, runtime.EventQuery{
		Since: sinceTime,
		Limit: 5000,
	})
	if err != nil {
		s.logger.Warn("runtime graph: QueryEvents failed; falling back to legacy", "error", err)
		return nil, false
	}
	if len(events) == 0 {
		// No runtime evidence at all in the window. Caller
		// falls back to legacy so pre-3B installs and existing
		// fixtures keep rendering.
		return nil, false
	}

	// Drop heartbeat-session rows from the projection. They are
	// diagnostic and must never inflate the graph. The presence
	// of heartbeat rows DID flip the usable=true return above,
	// so a heartbeat-only window correctly produces an empty
	// runtime graph (no fallback to legacy).
	realEvents := events[:0]
	for _, ev := range events {
		if runtime.IsHeartbeatSession(ev.SessionID) {
			continue
		}
		realEvents = append(realEvents, ev)
	}

	actors, err := store.QueryActors(ctx, runtime.ActorQuery{Limit: 5000})
	if err != nil {
		s.logger.Warn("runtime graph: QueryActors failed; falling back to legacy", "error", err)
		return nil, false
	}

	return projectRuntimeGraph(realEvents, actors), true
}

// projectRuntimeGraph is the pure projection from runtime rows
// into graph inputs. Pulled out of buildRuntimeGraph so tests can
// exercise it without spinning up a Store.
func projectRuntimeGraph(events []runtime.HookEvent, actors []runtime.Actor) *graph.AgentGraph {
	actorByID := indexActors(actors)
	agents, edgeStats, toolNodes, toolEdges := rollupRuntime(events, actorByID)
	g := graph.BuildObserved(agents, edgeStats)
	g.ToolNodes = toolNodes
	g.ToolEdges = toolEdges
	return g
}

// indexActors gives O(1) lookup by runtime actor id so the
// edge/projection loops below do not pay an O(n^2) scan.
func indexActors(actors []runtime.Actor) map[string]runtime.Actor {
	out := make(map[string]runtime.Actor, len(actors))
	for _, a := range actors {
		out[a.ID] = a
	}
	return out
}

// rollupRuntime walks the events slice once and produces:
//
//   - agent metadata for every actor that sourced or received an event;
//   - actor->actor edges (parent->child) keyed by event activity;
//   - tool nodes + actor->tool edges deduped per call.
//
// Tool dedupe rule:
//
//   - With ToolUseID: scope by (session, actor, tool_use_id). Pre+Post
//     pairs collapse to one count; the first event observed wins.
//   - Without ToolUseID: scope by (session, actor, tool_name). Some
//     hook payloads emit only PostToolUse and never carry a use_id,
//     so we cannot rely on stage filtering — counting only
//     pre-action would silently drop those calls. Instead we bucket
//     by (session, actor, tool) and count once: prefer a pre-action
//     row when present so the count lines up with "calls initiated",
//     but if the bucket is post-only we still record exactly one
//     edge so post-only evidence does not vanish from the graph.
//
// The bucket pass is a two-pass walk to keep the result stable
// regardless of event order (QueryEvents returns DESC, but the
// rule must hold for any input order).
func rollupRuntime(events []runtime.HookEvent, actorByID map[string]runtime.Actor) ([]graph.AgentMeta, []graph.EdgeInput, []graph.ToolNode, []graph.ToolEdge) {
	type edgeKey struct{ from, to string }
	type toolEdgeKey struct{ agent, tool string }
	type useIDKey struct{ session, actor, useID string }
	type noUseKey struct{ session, actor, tool string }

	agentMeta := make(map[string]graph.AgentMeta)
	edgeAgg := make(map[edgeKey]*graph.EdgeInput)
	toolEdgeAgg := make(map[toolEdgeKey]int)
	toolTotals := make(map[string]int)
	useIDSeen := make(map[useIDKey]bool)
	noUseHasPre := make(map[noUseKey]bool)
	noUseAny := make(map[noUseKey]runtime.HookEvent)

	displayLabel := func(actorID string) string {
		a, ok := actorByID[actorID]
		if !ok {
			return fallbackActorLabel(actorID)
		}
		return runtimeActorDisplayName(a)
	}
	registerAgent := func(actorID string) {
		name := displayLabel(actorID)
		if _, ok := agentMeta[name]; ok {
			return
		}
		kind := actorKind(actorID, actorByID)
		agentMeta[name] = graph.AgentMeta{
			Name:       name,
			Kind:       kind,
			CanMessage: []string{"*"}, // observed actors carry no ACL; wildcard avoids phantom shadow
		}
	}
	recordToolEdge := func(actorID, toolName string) {
		actorName := displayLabel(actorID)
		clean := stripGatewayNamespace(toolName)
		toolEdgeAgg[toolEdgeKey{agent: actorName, tool: clean}]++
		toolTotals[clean]++
	}

	for _, ev := range events {
		if ev.ActorID == "" {
			continue
		}
		registerAgent(ev.ActorID)
		actorName := displayLabel(ev.ActorID)

		// Actor->actor edge when the row points at a parent
		// distinct from the actor itself. Missing parent rows
		// fall back to the parent id so we never drop the edge.
		if ev.ParentActorID != "" && ev.ParentActorID != ev.ActorID {
			parentName := displayLabel(ev.ParentActorID)
			registerAgent(ev.ParentActorID)
			k := edgeKey{from: parentName, to: actorName}
			if e, ok := edgeAgg[k]; ok {
				e.Total++
				accumulateOutcome(e, ev)
			} else {
				e := &graph.EdgeInput{From: parentName, To: actorName, Total: 1}
				accumulateOutcome(e, ev)
				edgeAgg[k] = e
			}
		}

		if ev.ToolName == "" {
			continue
		}

		if ev.ToolUseID != "" {
			k := useIDKey{session: ev.SessionID, actor: ev.ActorID, useID: ev.ToolUseID}
			if useIDSeen[k] {
				continue
			}
			useIDSeen[k] = true
			recordToolEdge(ev.ActorID, ev.ToolName)
			continue
		}

		// No use_id: defer to second pass so the count is
		// independent of event order (QueryEvents is DESC).
		bucket := noUseKey{session: ev.SessionID, actor: ev.ActorID, tool: ev.ToolName}
		if ev.Stage == runtime.StagePreAction {
			if !noUseHasPre[bucket] {
				noUseHasPre[bucket] = true
				recordToolEdge(ev.ActorID, ev.ToolName)
			}
			continue
		}
		// Post-action / observed-only / unknown stage. Stash the
		// first one we see; a pre-action row in the same bucket
		// will take precedence when materialised.
		if _, ok := noUseAny[bucket]; !ok {
			noUseAny[bucket] = ev
		}
	}

	// Second pass: emit one tool edge per no-use_id bucket that
	// never saw a pre-action. Pre-action buckets already counted
	// above; visiting them again would double the edge.
	for bucket, ev := range noUseAny {
		if noUseHasPre[bucket] {
			continue
		}
		recordToolEdge(ev.ActorID, ev.ToolName)
	}

	// Materialise agents in deterministic order.
	agents := make([]graph.AgentMeta, 0, len(agentMeta))
	for _, a := range agentMeta {
		agents = append(agents, a)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })

	// Materialise edges.
	edges := make([]graph.EdgeInput, 0, len(edgeAgg))
	for _, e := range edgeAgg {
		edges = append(edges, *e)
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})

	// Top tools by total invocations (same cap as legacy graph).
	type toolRank struct {
		name  string
		total int
	}
	ranked := make([]toolRank, 0, len(toolTotals))
	for name, total := range toolTotals {
		ranked = append(ranked, toolRank{name, total})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].total != ranked[j].total {
			return ranked[i].total > ranked[j].total
		}
		return ranked[i].name < ranked[j].name
	})
	topTools := make(map[string]bool)
	toolNodes := make([]graph.ToolNode, 0, runtimeGraphTopTools)
	for _, r := range ranked {
		if len(toolNodes) >= runtimeGraphTopTools {
			break
		}
		topTools[r.name] = true
		toolNodes = append(toolNodes, graph.ToolNode{Name: r.name, Total: r.total})
	}

	toolEdges := make([]graph.ToolEdge, 0, len(toolEdgeAgg))
	for k, total := range toolEdgeAgg {
		if !topTools[k.tool] {
			continue
		}
		toolEdges = append(toolEdges, graph.ToolEdge{Agent: k.agent, Tool: k.tool, Total: total})
	}
	sort.Slice(toolEdges, func(i, j int) bool {
		if toolEdges[i].Agent != toolEdges[j].Agent {
			return toolEdges[i].Agent < toolEdges[j].Agent
		}
		return toolEdges[i].Tool < toolEdges[j].Tool
	})

	return agents, edges, toolNodes, toolEdges
}

// accumulateOutcome maps the per-event policy decision and status
// onto the EdgeInput counters. Generic rule:
//
//   - status=blocked OR policy_decision in {block, deny} → Blocked
//   - status=quarantined → Quarantined
//   - status=rejected → Rejected
//   - everything else (allow, delivered, empty) → Delivered
//
// Total is bumped by the caller; this helper only fills the
// per-status buckets so the final HealthScore reflects the mix.
func accumulateOutcome(e *graph.EdgeInput, ev runtime.HookEvent) {
	switch strings.ToLower(ev.Status) {
	case "blocked":
		e.Blocked++
		return
	case "quarantined":
		e.Quarantined++
		return
	case "rejected":
		e.Rejected++
		return
	}
	switch strings.ToLower(ev.PolicyDecision) {
	case "block", "deny":
		e.Blocked++
		return
	}
	e.Delivered++
}

// runtimeActorDisplayName picks the operator-visible name for one
// runtime actor. Generic rule:
//
//   - root: actor.PrincipalID (the resolved client identity),
//     falling back to actor.Label only when no principal is set.
//     The Phase 3A normalizer wrote a "root (clientID)" wrapper
//     label that is too long for a graph node; the principal
//     id is the canonical short form.
//   - subagent: subagent/<label-or-id-tail>
//   - task: task/<label-or-id-tail>
//   - other: actor/<id-tail>
//
// PrincipalID is only used as the root node label here. Subagent
// and task nodes never reuse the principal — actor metadata
// drives those names so the policy identity (one per session)
// stays distinct from the runtime actor (many per session).
func runtimeActorDisplayName(a runtime.Actor) string {
	switch a.Kind {
	case runtime.ActorKindRoot:
		if a.PrincipalID != "" {
			return a.PrincipalID
		}
		if a.Label != "" {
			return a.Label
		}
		return fallbackActorLabel(a.ID)
	case runtime.ActorKindSubagent:
		return "subagent/" + nonEmpty(a.Label, actorIDTail(a.ID))
	case runtime.ActorKindTask:
		return "task/" + nonEmpty(a.Label, actorIDTail(a.ID))
	default:
		return "actor/" + actorIDTail(a.ID)
	}
}

// fallbackActorLabel handles the edge case where rollupRuntime
// references an actor row that QueryActors did not return (e.g. a
// timing window or a row trimmed by the limit). The fallback
// keeps the node in a reasonable bucket so the parent edge does
// not vanish; for a root id we keep the literal "root" because
// no principal id is available in this branch (the actor row
// itself is what would have carried it).
func fallbackActorLabel(actorID string) string {
	if actorID == "" {
		return "unknown"
	}
	if strings.HasSuffix(actorID, ":root") {
		return "root"
	}
	if strings.Contains(actorID, ":subagent:") || strings.Contains(actorID, ":subagent-type:") {
		return "subagent/" + actorIDTail(actorID)
	}
	if strings.Contains(actorID, ":task:") {
		return "task/" + actorIDTail(actorID)
	}
	return "actor/" + actorIDTail(actorID)
}

// actorKind reads the Kind from the indexed actor when present,
// otherwise infers from the id pattern. Used by registerAgent to
// stamp the AgentMeta.Kind that ends up on graph.Node.
func actorKind(actorID string, actors map[string]runtime.Actor) string {
	if a, ok := actors[actorID]; ok && a.Kind != "" {
		return a.Kind
	}
	switch {
	case strings.HasSuffix(actorID, ":root"):
		return runtime.ActorKindRoot
	case strings.Contains(actorID, ":subagent:"), strings.Contains(actorID, ":subagent-type:"):
		return runtime.ActorKindSubagent
	case strings.Contains(actorID, ":task:"):
		return runtime.ActorKindTask
	}
	return runtime.ActorKindUnknown
}

// actorIDTail returns the trailing component of a structured
// actor id (everything after the last colon). Used so subagent
// labels read "subagent/sa-1" instead of leaking the full
// session-prefixed id.
func actorIDTail(id string) string {
	if id == "" {
		return ""
	}
	if i := strings.LastIndex(id, ":"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

// nonEmpty picks the first non-empty argument. Local helper to
// keep the display-name switches readable.
func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// stripGatewayNamespace mirrors the legacy graph behavior: tool
// names like "mcp__oktsec-gateway__Read" render as "Read" so the
// runtime and audit paths display the same node name.
func stripGatewayNamespace(name string) string {
	if i := strings.LastIndex(name, "__"); i >= 0 && i < len(name)-2 {
		return name[i+2:]
	}
	return name
}

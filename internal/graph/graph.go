// Package graph computes agent interaction graphs from audit data and ACL config.
// Pure computation — no imports from other internal packages.
package graph

import "math"

// AgentMeta describes an agent from config (decoupled from config.Agent).
type AgentMeta struct {
	Name        string
	Description string
	Location    string
	Tags        []string
	CanMessage  []string
}

// EdgeInput describes observed traffic on a single from→to edge.
type EdgeInput struct {
	From        string
	To          string
	Delivered   int
	Blocked     int
	Quarantined int
	Rejected    int
	Total       int
}

// Node is a computed graph node with metrics.
type Node struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Location    string   `json:"location,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	InDegree    int      `json:"in_degree"`
	OutDegree   int      `json:"out_degree"`
	Betweenness float64  `json:"betweenness"`
	ThreatScore float64  `json:"threat_score"`
	TotalSent   int      `json:"total_sent"`
	TotalRecv   int      `json:"total_recv"`
	BlockedSent int      `json:"blocked_sent"`
	BlockedRecv int      `json:"blocked_recv"`
}

// Edge is a computed graph edge with health metrics.
type Edge struct {
	From        string  `json:"from"`
	To          string  `json:"to"`
	Delivered   int     `json:"delivered"`
	Blocked     int     `json:"blocked"`
	Quarantined int     `json:"quarantined"`
	Rejected    int     `json:"rejected"`
	Total       int     `json:"total"`
	HealthScore float64 `json:"health_score"`
}

// ACLEdge represents a permitted communication path from the ACL config.
type ACLEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Active bool   `json:"active"`
}

// ShadowEdge represents traffic observed between agents not in the ACL.
type ShadowEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Total int    `json:"total"`
}

// AgentGraph is the complete computed interaction graph.
type AgentGraph struct {
	Nodes       []Node       `json:"nodes"`
	Edges       []Edge       `json:"edges"`
	ACLEdges    []ACLEdge    `json:"acl_edges"`
	ShadowEdges []ShadowEdge `json:"shadow_edges"`
	UnusedACL   []ACLEdge    `json:"unused_acl"`
	TotalNodes  int          `json:"total_nodes"`
	TotalEdges  int          `json:"total_edges"`
}

// Build constructs the full agent interaction graph from config agents and observed edges.
func Build(agents []AgentMeta, edges []EdgeInput) *AgentGraph {
	nodeMap := buildNodeSet(agents, edges)
	computed := buildEdges(edges)
	computeDegrees(nodeMap, computed)
	computeBetweenness(nodeMap, computed)
	computeThreatScores(nodeMap, edges)
	aclEdges, shadowEdges, unusedACL := compareACL(agents, edges)

	nodes := make([]Node, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, *n)
	}

	return &AgentGraph{
		Nodes:       nodes,
		Edges:       computed,
		ACLEdges:    aclEdges,
		ShadowEdges: shadowEdges,
		UnusedACL:   unusedACL,
		TotalNodes:  len(nodes),
		TotalEdges:  len(computed),
	}
}

// buildNodeSet merges config agents with agents seen in edges.
func buildNodeSet(agents []AgentMeta, edges []EdgeInput) map[string]*Node {
	nodeMap := make(map[string]*Node)
	for _, a := range agents {
		nodeMap[a.Name] = &Node{
			Name:        a.Name,
			Description: a.Description,
			Location:    a.Location,
			Tags:        a.Tags,
			Betweenness: -1,
		}
	}
	for _, e := range edges {
		if _, ok := nodeMap[e.From]; !ok {
			nodeMap[e.From] = &Node{Name: e.From, Betweenness: -1}
		}
		if _, ok := nodeMap[e.To]; !ok {
			nodeMap[e.To] = &Node{Name: e.To, Betweenness: -1}
		}
	}
	return nodeMap
}

// buildEdges converts EdgeInput to Edge with computed health scores.
func buildEdges(edges []EdgeInput) []Edge {
	result := make([]Edge, 0, len(edges))
	for _, e := range edges {
		health := 100.0
		if e.Total > 0 {
			health = float64(e.Delivered) / float64(e.Total) * 100
		}
		result = append(result, Edge{
			From:        e.From,
			To:          e.To,
			Delivered:   e.Delivered,
			Blocked:     e.Blocked,
			Quarantined: e.Quarantined,
			Rejected:    e.Rejected,
			Total:       e.Total,
			HealthScore: math.Round(health*10) / 10,
		})
	}
	return result
}

// computeDegrees sets in/out degree and sent/recv totals per node.
func computeDegrees(nodeMap map[string]*Node, edges []Edge) {
	for _, e := range edges {
		if n, ok := nodeMap[e.From]; ok {
			n.OutDegree++
			n.TotalSent += e.Total
			n.BlockedSent += e.Blocked
		}
		if n, ok := nodeMap[e.To]; ok {
			n.InDegree++
			n.TotalRecv += e.Total
			n.BlockedRecv += e.Blocked
		}
	}
}

const betweennessNodeLimit = 50

// computeBetweenness runs BFS-based betweenness centrality, skipping large graphs.
func computeBetweenness(nodeMap map[string]*Node, edges []Edge) {
	if len(nodeMap) >= betweennessNodeLimit {
		return // all remain -1
	}

	// Build adjacency list
	names := make([]string, 0, len(nodeMap))
	idx := make(map[string]int)
	for name := range nodeMap {
		idx[name] = len(names)
		names = append(names, name)
	}

	n := len(names)
	adj := make([][]int, n)
	for i := range adj {
		adj[i] = []int{}
	}
	for _, e := range edges {
		adj[idx[e.From]] = append(adj[idx[e.From]], idx[e.To])
	}

	// Brandes' algorithm
	cb := make([]float64, n)
	for s := range n {
		brandesBFS(s, n, adj, cb)
	}

	// Normalize: max possible is (n-1)*(n-2) for directed graphs
	maxVal := float64((n - 1) * (n - 2))
	for name, node := range nodeMap {
		if maxVal > 0 {
			node.Betweenness = math.Round(cb[idx[name]]/maxVal*1000) / 1000
		} else {
			node.Betweenness = 0
		}
	}
}

// brandesBFS runs one BFS pass of Brandes' algorithm from source s, accumulating into cb.
func brandesBFS(s, n int, adj [][]int, cb []float64) {
	stack := make([]int, 0, n)
	pred := make([][]int, n)
	sigma := make([]float64, n)
	sigma[s] = 1
	dist := make([]int, n)
	for i := range dist {
		dist[i] = -1
	}
	dist[s] = 0

	queue := []int{s}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		stack = append(stack, v)
		for _, w := range adj[v] {
			if dist[w] < 0 {
				queue = append(queue, w)
				dist[w] = dist[v] + 1
			}
			if dist[w] == dist[v]+1 {
				sigma[w] += sigma[v]
				pred[w] = append(pred[w], v)
			}
		}
	}

	delta := make([]float64, n)
	for len(stack) > 0 {
		w := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, v := range pred[w] {
			delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
		}
		if w != s {
			cb[w] += delta[w]
		}
	}
}

// computeThreatScores sets composite threat scores per node.
// Formula: 0.4*blockRatio + 0.3*incomingToxic + 0.2*normalizedDegree + 0.1*quarantineRatio
func computeThreatScores(nodeMap map[string]*Node, edges []EdgeInput) {
	// Aggregate per-node stats from edges
	type stats struct {
		sentTotal, sentBlocked, sentQuarantined int
		recvTotal, recvBlocked                  int
	}
	s := make(map[string]*stats)
	for name := range nodeMap {
		s[name] = &stats{}
	}
	for _, e := range edges {
		if st, ok := s[e.From]; ok {
			st.sentTotal += e.Total
			st.sentBlocked += e.Blocked
			st.sentQuarantined += e.Quarantined
		}
		if st, ok := s[e.To]; ok {
			st.recvTotal += e.Total
			st.recvBlocked += e.Blocked
		}
	}

	// Find max degree for normalization
	var maxDeg int
	for _, n := range nodeMap {
		deg := n.InDegree + n.OutDegree
		if deg > maxDeg {
			maxDeg = deg
		}
	}

	for name, node := range nodeMap {
		st := s[name]
		var blockRatio, quarantineRatio, incomingToxic, normDeg float64

		if st.sentTotal > 0 {
			blockRatio = float64(st.sentBlocked) / float64(st.sentTotal)
			quarantineRatio = float64(st.sentQuarantined) / float64(st.sentTotal)
		}
		if st.recvTotal > 0 {
			incomingToxic = float64(st.recvBlocked) / float64(st.recvTotal)
		}
		if maxDeg > 0 {
			normDeg = float64(node.InDegree+node.OutDegree) / float64(maxDeg)
		}

		score := (0.4*blockRatio + 0.3*incomingToxic + 0.2*normDeg + 0.1*quarantineRatio) * 100
		node.ThreatScore = math.Round(score*10) / 10
	}
}

// compareACL diffs the policy graph against actual traffic.
func compareACL(agents []AgentMeta, edges []EdgeInput) ([]ACLEdge, []ShadowEdge, []ACLEdge) {
	// Build set of ACL-permitted edges
	type pair struct{ from, to string }
	aclSet := make(map[pair]bool)
	configAgents := make(map[string]bool)
	for _, a := range agents {
		configAgents[a.Name] = true
		for _, target := range a.CanMessage {
			aclSet[pair{a.Name, target}] = true
		}
	}

	// Build set of actual traffic edges
	actualSet := make(map[pair]int)
	for _, e := range edges {
		actualSet[pair{e.From, e.To}] = e.Total
	}

	// ACL edges: mark active if traffic exists
	var aclEdges []ACLEdge
	var unusedACL []ACLEdge
	for p := range aclSet {
		active := actualSet[p] > 0
		ae := ACLEdge{From: p.from, To: p.to, Active: active}
		aclEdges = append(aclEdges, ae)
		if !active {
			unusedACL = append(unusedACL, ae)
		}
	}

	// Shadow edges: traffic not in ACL
	var shadowEdges []ShadowEdge
	for p, total := range actualSet {
		if !aclSet[p] {
			shadowEdges = append(shadowEdges, ShadowEdge{From: p.from, To: p.to, Total: total})
		}
	}

	return aclEdges, shadowEdges, unusedACL
}

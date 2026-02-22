package graph

import "testing"

func TestBuild_BasicGraph(t *testing.T) {
	agents := []AgentMeta{
		{Name: "a", Description: "Agent A", CanMessage: []string{"b", "c"}},
		{Name: "b", Description: "Agent B", CanMessage: []string{"c"}},
		{Name: "c", Description: "Agent C"},
	}
	edges := []EdgeInput{
		{From: "a", To: "b", Delivered: 8, Blocked: 2, Total: 10},
		{From: "a", To: "c", Delivered: 5, Total: 5},
		{From: "b", To: "c", Delivered: 3, Blocked: 1, Total: 4},
		{From: "c", To: "a", Delivered: 1, Total: 1},
	}

	g := Build(agents, edges)
	if g.TotalNodes != 3 {
		t.Errorf("total_nodes = %d, want 3", g.TotalNodes)
	}
	if g.TotalEdges != 4 {
		t.Errorf("total_edges = %d, want 4", g.TotalEdges)
	}

	nodeMap := make(map[string]Node)
	for _, n := range g.Nodes {
		nodeMap[n.Name] = n
	}

	// Agent a: out_degree=2, in_degree=1
	if nodeMap["a"].OutDegree != 2 {
		t.Errorf("a out_degree = %d, want 2", nodeMap["a"].OutDegree)
	}
	if nodeMap["a"].InDegree != 1 {
		t.Errorf("a in_degree = %d, want 1", nodeMap["a"].InDegree)
	}
	// Agent a sends 15 total, 2 blocked
	if nodeMap["a"].TotalSent != 15 {
		t.Errorf("a total_sent = %d, want 15", nodeMap["a"].TotalSent)
	}

	// Threat scores should be non-negative
	for name, n := range nodeMap {
		if n.ThreatScore < 0 {
			t.Errorf("%s threat_score = %f, want >= 0", name, n.ThreatScore)
		}
	}
}

func TestBuild_EmptyEdges(t *testing.T) {
	agents := []AgentMeta{
		{Name: "x", CanMessage: []string{"y"}},
		{Name: "y"},
	}

	g := Build(agents, nil)
	if g.TotalNodes != 2 {
		t.Errorf("total_nodes = %d, want 2", g.TotalNodes)
	}
	if g.TotalEdges != 0 {
		t.Errorf("total_edges = %d, want 0", g.TotalEdges)
	}

	for _, n := range g.Nodes {
		if n.ThreatScore != 0 {
			t.Errorf("%s threat_score = %f, want 0", n.Name, n.ThreatScore)
		}
		if n.InDegree != 0 || n.OutDegree != 0 {
			t.Errorf("%s degree should be 0", n.Name)
		}
	}

	// x→y is permitted but unused
	if len(g.UnusedACL) != 1 {
		t.Errorf("unused_acl = %d, want 1", len(g.UnusedACL))
	}
}

func TestBuild_ShadowEdges(t *testing.T) {
	agents := []AgentMeta{
		{Name: "a", CanMessage: []string{"b"}},
		{Name: "b"},
	}
	edges := []EdgeInput{
		{From: "a", To: "b", Delivered: 5, Total: 5},
		{From: "unknown", To: "b", Delivered: 3, Total: 3}, // shadow: unknown not in config
	}

	g := Build(agents, edges)
	if len(g.ShadowEdges) != 1 {
		t.Fatalf("shadow_edges = %d, want 1", len(g.ShadowEdges))
	}
	if g.ShadowEdges[0].From != "unknown" {
		t.Errorf("shadow from = %q, want 'unknown'", g.ShadowEdges[0].From)
	}

	// unknown agent should appear as a node
	if g.TotalNodes != 3 {
		t.Errorf("total_nodes = %d, want 3 (a, b, unknown)", g.TotalNodes)
	}
}

func TestBuild_UnusedACL(t *testing.T) {
	agents := []AgentMeta{
		{Name: "a", CanMessage: []string{"b", "c"}},
		{Name: "b"},
		{Name: "c"},
	}
	edges := []EdgeInput{
		{From: "a", To: "b", Delivered: 1, Total: 1},
		// a→c is permitted but no traffic
	}

	g := Build(agents, edges)
	if len(g.UnusedACL) != 1 {
		t.Fatalf("unused_acl = %d, want 1", len(g.UnusedACL))
	}
	if g.UnusedACL[0].To != "c" {
		t.Errorf("unused ACL to = %q, want 'c'", g.UnusedACL[0].To)
	}
}

func TestBetweenness_StarTopology(t *testing.T) {
	// Star: center connects to all spokes, spokes connect only through center
	agents := []AgentMeta{
		{Name: "center"},
		{Name: "s1"},
		{Name: "s2"},
		{Name: "s3"},
	}
	edges := []EdgeInput{
		{From: "s1", To: "center", Delivered: 1, Total: 1},
		{From: "s2", To: "center", Delivered: 1, Total: 1},
		{From: "s3", To: "center", Delivered: 1, Total: 1},
		{From: "center", To: "s1", Delivered: 1, Total: 1},
		{From: "center", To: "s2", Delivered: 1, Total: 1},
		{From: "center", To: "s3", Delivered: 1, Total: 1},
	}

	g := Build(agents, edges)
	nodeMap := make(map[string]Node)
	for _, n := range g.Nodes {
		nodeMap[n.Name] = n
	}

	// Center should have highest betweenness
	center := nodeMap["center"]
	for _, spoke := range []string{"s1", "s2", "s3"} {
		if nodeMap[spoke].Betweenness > center.Betweenness {
			t.Errorf("spoke %s betweenness (%f) > center (%f)", spoke, nodeMap[spoke].Betweenness, center.Betweenness)
		}
	}
}

func TestBetweenness_SkipsLargeGraph(t *testing.T) {
	agents := make([]AgentMeta, betweennessNodeLimit)
	for i := range agents {
		agents[i] = AgentMeta{Name: string(rune('A'+i%26)) + string(rune('0'+i/26))}
	}

	g := Build(agents, nil)
	for _, n := range g.Nodes {
		if n.Betweenness != -1 {
			t.Errorf("%s betweenness = %f, want -1 (skipped)", n.Name, n.Betweenness)
		}
	}
}

func TestHealthScore(t *testing.T) {
	cases := []struct {
		name      string
		delivered int
		total     int
		want      float64
	}{
		{"total zero", 0, 0, 100},
		{"all delivered", 10, 10, 100},
		{"all blocked", 0, 10, 0},
		{"half", 5, 10, 50},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edges := []EdgeInput{{From: "a", To: "b", Delivered: tc.delivered, Blocked: tc.total - tc.delivered, Total: tc.total}}
			g := Build(nil, edges)
			if len(g.Edges) != 1 {
				t.Fatal("expected 1 edge")
			}
			if g.Edges[0].HealthScore != tc.want {
				t.Errorf("health = %f, want %f", g.Edges[0].HealthScore, tc.want)
			}
		})
	}
}

func TestThreatScore(t *testing.T) {
	// Agent with all traffic blocked should score high
	agents := []AgentMeta{{Name: "bad"}, {Name: "good"}, {Name: "target"}}
	edges := []EdgeInput{
		{From: "bad", To: "target", Blocked: 10, Total: 10},
		{From: "good", To: "target", Delivered: 10, Total: 10},
	}

	g := Build(agents, edges)
	nodeMap := make(map[string]Node)
	for _, n := range g.Nodes {
		nodeMap[n.Name] = n
	}

	if nodeMap["bad"].ThreatScore <= nodeMap["good"].ThreatScore {
		t.Errorf("bad threat (%f) should be > good threat (%f)", nodeMap["bad"].ThreatScore, nodeMap["good"].ThreatScore)
	}
	if nodeMap["good"].ThreatScore != 0 {
		// good sends only delivered messages, zero blocks
		// but it still has a degree component, so let's check it's low
		if nodeMap["good"].ThreatScore > 25 {
			t.Errorf("good threat = %f, should be low", nodeMap["good"].ThreatScore)
		}
	}
}

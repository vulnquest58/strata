package graph

import (
	"context"
	"strings"
	"testing"
	"time"

	"aperture/internal/model"
)

type mockStore struct {
	fps   []*model.InfrastructureFingerprint
	corrs []*model.CrossTargetCorrelation
}

func (m *mockStore) UpsertFinding(ctx context.Context, f *model.Finding) error           { return nil }
func (m *mockStore) GetFindingsByScanID(ctx context.Context, scanID string) ([]*model.Finding, error) {
	return nil, nil
}
func (m *mockStore) IncrementConsensusCount(ctx context.Context, scanID, assetID string) error {
	return nil
}
func (m *mockStore) GetReliability(ctx context.Context, source, domainPattern string) (*model.SourceReliabilityRecord, error) {
	return nil, nil
}
func (m *mockStore) SaveReliability(ctx context.Context, r *model.SourceReliabilityRecord) error {
	return nil
}
func (m *mockStore) ListReliability(ctx context.Context, source string) ([]*model.SourceReliabilityRecord, error) {
	return nil, nil
}
func (m *mockStore) SampleUnverifiedFindings(ctx context.Context, source string, sampleRate float64, olderThan time.Duration) ([]*model.Finding, error) {
	return nil, nil
}
func (m *mockStore) MarkFindingVerified(ctx context.Context, findingID string, live bool) error {
	return nil
}
func (m *mockStore) SaveFingerprint(ctx context.Context, fp *model.InfrastructureFingerprint) error {
	return nil
}
func (m *mockStore) GetFingerprints(ctx context.Context, rootDomain string) ([]*model.InfrastructureFingerprint, error) {
	return m.fps, nil
}
func (m *mockStore) SaveCorrelation(ctx context.Context, c *model.CrossTargetCorrelation) error {
	return nil
}
func (m *mockStore) ListCorrelations(ctx context.Context, rootDomain string) ([]*model.CrossTargetCorrelation, error) {
	return m.corrs, nil
}
func (m *mockStore) Close() error { return nil }

func TestGraphBuilderAndQuery(t *testing.T) {
	now := time.Now().UTC()

	mock := &mockStore{
		fps: []*model.InfrastructureFingerprint{
			{
				AssetID:     "action.github.com",
				RootDomain:  "github.com",
				ResolvedIPs: []string{"185.199.108.153"},
				IPRanges24:  []string{"185.199.108.0/24"},
				ASN:         54113,
				ASOrg:       "FASTLY - Fastly, Inc., US",
				ExtractedAt: now,
			},
			{
				AssetID:     "analytics.githubassets.com",
				RootDomain:  "githubassets.com",
				ResolvedIPs: []string{"185.199.108.153"},
				IPRanges24:  []string{"185.199.108.0/24"},
				ASN:         54113,
				ASOrg:       "FASTLY - Fastly, Inc., US",
				ExtractedAt: now,
			},
		},
		corrs: []*model.CrossTargetCorrelation{
			{
				ID:              "corr-1",
				RootDomainA:     "github.com",
				RootDomainB:     "githubassets.com",
				AssetA:          "action.github.com",
				AssetB:          "analytics.githubassets.com",
				CorrelationType: "shared_subnet_24",
				SharedElement:   "185.199.108.0/24",
				Confidence:      0.72,
				DiscoveredAt:    now,
			},
		},
	}

	builder := NewBuilder(mock)
	g, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify Node Presence
	expectedNodes := []string{
		"domain:github.com",
		"domain:githubassets.com",
		"asset:action.github.com",
		"asset:analytics.githubassets.com",
		"ip:185.199.108.153",
		"asn:AS54113",
		"subnet:185.199.108.0/24",
	}

	for _, nID := range expectedNodes {
		if _, ok := g.Nodes[nID]; !ok {
			t.Errorf("expected node %q in graph", nID)
		}
	}

	// Verify BFS Traversal from github.com at depth 2
	sub, err := TraverseBFS(g, "github.com", 2)
	if err != nil {
		t.Fatalf("TraverseBFS failed: %v", err)
	}

	// Depth 1 connects domain -> asset (action.github.com) and domain -> correlated domain (githubassets.com)
	// Depth 2 connects asset -> ip and githubassets.com -> analytics.githubassets.com
	if _, ok := sub.Nodes["domain:githubassets.com"]; !ok {
		t.Errorf("expected githubassets.com to be discovered within depth 2 via correlation")
	}

	// Verify JSON export
	jsonBytes, err := sub.ExportJSON()
	if err != nil || len(jsonBytes) == 0 {
		t.Errorf("ExportJSON failed: %v", err)
	}

	// Verify DOT export
	dotStr := sub.ExportDOT()
	if !strings.Contains(dotStr, "digraph AttackSurface") {
		t.Errorf("ExportDOT missing digraph header")
	}
	if !strings.Contains(dotStr, "SHARES_SUBNET") {
		t.Errorf("ExportDOT missing SHARES_SUBNET edge label")
	}

	// Verify Edge Classification
	corrEdge := g.Edges["corr:github.com:githubassets.com:185.199.108.0/24"]
	if corrEdge == nil {
		t.Fatalf("expected correlation edge in graph")
	}
	if corrEdge.Classify() != ClassWeakColocation {
		t.Errorf("expected 0.72 subnet correlation to be classified as %s, got %s",
			ClassWeakColocation, corrEdge.Classify())
	}

	// High confidence correlation (>= 0.80)
	highConfEdge := &Edge{
		Type:       EdgeSharesSubnet,
		Confidence: 0.88,
	}
	if highConfEdge.Classify() != ClassHighConfidenceOrgLink {
		t.Errorf("expected 0.88 edge to be classified as %s, got %s",
			ClassHighConfidenceOrgLink, highConfEdge.Classify())
	}
}

// TestTraverseBFSOnlyOrgLinksPruning strictly proves that --org-only severs and prunes weak_colocation edges
// preventing multi-tenant CDN leakage to unrelated organizations.
func TestTraverseBFSOnlyOrgLinksPruning(t *testing.T) {
	g := NewGraph()

	// 1. Seed root domain A
	g.AddNode(&Node{ID: "domain:company-a.com", Type: NodeDomain, Label: "company-a.com"})
	g.AddNode(&Node{ID: "asset:api.company-a.com", Type: NodeAsset, Label: "api.company-a.com"})
	g.AddEdge(&Edge{
		ID:             "edge:sub:a",
		SourceID:       "asset:api.company-a.com",
		TargetID:       "domain:company-a.com",
		Type:           EdgeSubdomainOf,
		Confidence:     1.0,
		Classification: ClassStructural,
	})

	// 2. Target B (Genuine sister subsidiary - High Confidence Org Link)
	g.AddNode(&Node{ID: "domain:company-b.com", Type: NodeDomain, Label: "company-b.com"})
	g.AddNode(&Node{ID: "asset:portal.company-b.com", Type: NodeAsset, Label: "portal.company-b.com"})
	g.AddEdge(&Edge{
		ID:             "edge:sub:b",
		SourceID:       "asset:portal.company-b.com",
		TargetID:       "domain:company-b.com",
		Type:           EdgeSubdomainOf,
		Confidence:     1.0,
		Classification: ClassStructural,
	})
	g.AddEdge(&Edge{
		ID:             "corr:a:b",
		SourceID:       "domain:company-a.com",
		TargetID:       "domain:company-b.com",
		Type:           EdgeSharesSubnet,
		Confidence:     0.88,
		Classification: ClassHighConfidenceOrgLink,
	})

	// 3. Target C (Unrelated stranger on same CDN - Weak Co-location)
	g.AddNode(&Node{ID: "domain:stranger-cdn.com", Type: NodeDomain, Label: "stranger-cdn.com"})
	g.AddNode(&Node{ID: "asset:shop.stranger-cdn.com", Type: NodeAsset, Label: "shop.stranger-cdn.com"})
	g.AddEdge(&Edge{
		ID:             "edge:sub:c",
		SourceID:       "asset:shop.stranger-cdn.com",
		TargetID:       "domain:stranger-cdn.com",
		Type:           EdgeSubdomainOf,
		Confidence:     1.0,
		Classification: ClassStructural,
	})
	g.AddEdge(&Edge{
		ID:             "corr:a:c",
		SourceID:       "domain:company-a.com",
		TargetID:       "domain:stranger-cdn.com",
		Type:           EdgeSharesSubnet,
		Confidence:     0.49,
		Classification: ClassWeakColocation,
	})

	// Run A: Traversal WITHOUT --org-only (baseline: visits all connected domains)
	subAll, err := TraverseBFSOpt(g, "company-a.com", TraversalOptions{
		MaxDepth:     2,
		OnlyOrgLinks: false,
	})
	if err != nil {
		t.Fatalf("TraverseBFSOpt failed: %v", err)
	}

	if _, ok := subAll.Nodes["domain:company-b.com"]; !ok {
		t.Errorf("baseline expected company-b.com in graph")
	}
	if _, ok := subAll.Nodes["domain:stranger-cdn.com"]; !ok {
		t.Errorf("baseline expected stranger-cdn.com in graph without filter")
	}

	// Run B: Traversal WITH --org-only (enforces strict organizational isolation)
	subOrgOnly, err := TraverseBFSOpt(g, "company-a.com", TraversalOptions{
		MaxDepth:     2,
		OnlyOrgLinks: true,
	})
	if err != nil {
		t.Fatalf("TraverseBFSOpt with --org-only failed: %v", err)
	}

	// Verification 1: True Positive (company-b.com) is preserved
	if _, ok := subOrgOnly.Nodes["domain:company-b.com"]; !ok {
		t.Errorf("expected high_confidence_org_link company-b.com to be preserved under --org-only")
	}
	if _, ok := subOrgOnly.Edges["corr:a:b"]; !ok {
		t.Errorf("expected correlation edge corr:a:b to be preserved under --org-only")
	}

	// Verification 2: False Positive / Weak Co-location (stranger-cdn.com) is strictly PRUNED
	if _, ok := subOrgOnly.Nodes["domain:stranger-cdn.com"]; ok {
		t.Errorf("FAILED: weak_colocation stranger domain was NOT pruned by --org-only")
	}
	if _, ok := subOrgOnly.Nodes["asset:shop.stranger-cdn.com"]; ok {
		t.Errorf("FAILED: child asset of weak_colocation stranger domain leaked into graph")
	}
	if _, ok := subOrgOnly.Edges["corr:a:c"]; ok {
		t.Errorf("FAILED: weak_colocation edge corr:a:c was NOT pruned by --org-only")
	}

	t.Logf("Pruning Verified: --org-only kept company-b.com (high_confidence_org_link) and successfully pruned stranger-cdn.com (weak_colocation)")
}

// TestGraphSaturation verifies graph convergence across traversal depth progression.
// It proves the existence of a definitive saturation depth d* where delta Nodes == 0.
func TestGraphSaturation(t *testing.T) {
	now := time.Now().UTC()
	mock := &mockStore{
		fps: []*model.InfrastructureFingerprint{
			{
				AssetID:     "action.github.com",
				RootDomain:  "github.com",
				ResolvedIPs: []string{"185.199.108.153"},
				IPRanges24:  []string{"185.199.108.0/24"},
				ASN:         54113,
				ASOrg:       "FASTLY - Fastly, Inc., US",
				ExtractedAt: now,
			},
			{
				AssetID:     "analytics.githubassets.com",
				RootDomain:  "githubassets.com",
				ResolvedIPs: []string{"185.199.108.153"},
				IPRanges24:  []string{"185.199.108.0/24"},
				ASN:         54113,
				ASOrg:       "FASTLY - Fastly, Inc., US",
				ExtractedAt: now,
			},
		},
		corrs: []*model.CrossTargetCorrelation{
			{
				ID:              "corr-1",
				RootDomainA:     "github.com",
				RootDomainB:     "githubassets.com",
				AssetA:          "action.github.com",
				AssetB:          "analytics.githubassets.com",
				CorrelationType: "shared_subnet_24",
				SharedElement:   "185.199.108.0/24",
				Confidence:      0.88,
				DiscoveredAt:    now,
			},
		},
	}

	builder := NewBuilder(mock)
	g, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	prevNodes := 0
	prevEdges := 0
	saturationDepth := -1

	for depth := 0; depth <= 5; depth++ {
		sub, err := TraverseBFS(g, "github.com", depth)
		if err != nil {
			t.Fatalf("depth %d traversal failed: %v", depth, err)
		}

		nodeCount := len(sub.Nodes)
		edgeCount := len(sub.Edges)
		deltaN := nodeCount - prevNodes
		deltaE := edgeCount - prevEdges

		t.Logf("Depth %d: Nodes=%d (delta=%d), Edges=%d (delta=%d)",
			depth, nodeCount, deltaN, edgeCount, deltaE)

		if depth > 0 && deltaN == 0 && deltaE == 0 && saturationDepth == -1 {
			saturationDepth = depth
		}

		prevNodes = nodeCount
		prevEdges = edgeCount
	}

	if saturationDepth == -1 {
		t.Errorf("expected graph to saturate within 5 hops, but no saturation point observed")
	} else {
		t.Logf("Saturation Verified: Graph fully saturated at Depth %d (no new nodes or edges discovered at depth > %d)",
			saturationDepth, saturationDepth)
	}
}

// TestDualEdgeOrgLinkAndCorporateAffiliationCoexistence verifies the graph behavior when two domains
// share BOTH a technical infrastructure link (high_confidence_org_link) and a registry corporate link (corporate_affiliation).
func TestDualEdgeOrgLinkAndCorporateAffiliationCoexistence(t *testing.T) {
	now := time.Now().UTC()
	mock := &mockStore{
		fps: []*model.InfrastructureFingerprint{
			{
				AssetID:      "github.com",
				RootDomain:   "github.com",
				ResolvedIPs:  []string{"140.82.121.4"},
				IPRanges24:   []string{"140.82.121.0/24"},
				ExtractedAt:  now,
			},
			{
				AssetID:      "githubassets.com",
				RootDomain:   "githubassets.com",
				ResolvedIPs:  []string{"185.199.108.153"},
				IPRanges24:   []string{"185.199.108.0/24"},
				ExtractedAt:  now,
			},
			{
				AssetID:      "stranger-cdn.com",
				RootDomain:   "stranger-cdn.com",
				ResolvedIPs:  []string{"185.199.108.99"},
				IPRanges24:   []string{"185.199.108.0/24"},
				ExtractedAt:  now,
			},
		},
		corrs: []*model.CrossTargetCorrelation{
			// 1. Technical infrastructure link (network layer)
			{
				RootDomainA:     "github.com",
				RootDomainB:     "githubassets.com",
				AssetA:          "github.com",
				AssetB:          "githubassets.com",
				CorrelationType: "shared_subnet_24",
				SharedElement:   "185.199.108.0/24",
				Confidence:      0.88,
				DiscoveredAt:    now,
			},
			// 2. Legal registry corporate affiliation link (WHOIS layer)
			{
				RootDomainA:     "github.com",
				RootDomainB:     "githubassets.com",
				AssetA:          "github.com",
				AssetB:          "githubassets.com",
				CorrelationType: "corporate_affiliation",
				SharedElement:   "whois_org:GitHub, Inc.",
				Confidence:      0.92,
				Evidence: map[string]any{
					"matched_org": "GitHub, Inc.",
					"registrar":   "Markmonitor Inc.",
				},
				DiscoveredAt: now,
			},
			// 3. Weak co-location on public CDN (must be pruned by --org-only)
			{
				RootDomainA:     "github.com",
				RootDomainB:     "stranger-cdn.com",
				AssetA:          "github.com",
				AssetB:          "stranger-cdn.com",
				CorrelationType: "shared_subnet_24",
				SharedElement:   "185.199.108.0/24",
				Confidence:      0.49,
				DiscoveredAt:    now,
			},
		},
	}

	builder := NewBuilder(mock)
	builder.SetMinConfidence(0.40)
	g, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// 1. Traverse with OnlyOrgLinks: true (simulating --org-only)
	subOrgOnly, err := TraverseBFSOpt(g, "github.com", TraversalOptions{
		MaxDepth:     2,
		OnlyOrgLinks: true,
	})
	if err != nil {
		t.Fatalf("traversal with --org-only failed: %v", err)
	}

	// Check nodes:
	if _, ok := subOrgOnly.Nodes["domain:github.com"]; !ok {
		t.Errorf("missing seed domain:github.com")
	}
	if _, ok := subOrgOnly.Nodes["domain:githubassets.com"]; !ok {
		t.Errorf("missing correlated domain:githubassets.com")
	}
	if _, ok := subOrgOnly.Nodes["domain:stranger-cdn.com"]; ok {
		t.Errorf("expected stranger-cdn.com (weak_colocation) to be pruned by --org-only")
	}

	// Count edges between github.com and githubassets.com
	var techEdges, corpEdges, weakEdges int
	for _, e := range subOrgOnly.Edges {
		if strings.HasPrefix(e.SourceID, "domain:") && strings.HasPrefix(e.TargetID, "domain:") {
			switch e.Classify() {
			case ClassHighConfidenceOrgLink:
				techEdges++
			case ClassCorporateAffiliation:
				corpEdges++
			case ClassWeakColocation:
				weakEdges++
			}
		}
	}

	if techEdges != 1 {
		t.Errorf("expected exactly 1 high_confidence_org_link edge between domains, got %d", techEdges)
	}
	if corpEdges != 1 {
		t.Errorf("expected exactly 1 corporate_affiliation edge between domains, got %d", corpEdges)
	}
	if weakEdges != 0 {
		t.Errorf("expected 0 weak_colocation edges under --org-only, got %d", weakEdges)
	}

	// 2. Traverse with Classification = "corporate_affiliation"
	subCorpOnly, err := TraverseBFSOpt(g, "github.com", TraversalOptions{
		MaxDepth:       2,
		Classification: ClassCorporateAffiliation,
	})
	if err != nil {
		t.Fatalf("traversal with --classification=corporate_affiliation failed: %v", err)
	}

	for _, e := range subCorpOnly.Edges {
		if strings.HasPrefix(e.SourceID, "domain:") && strings.HasPrefix(e.TargetID, "domain:") {
			if e.Classify() != ClassCorporateAffiliation {
				t.Errorf("expected only corporate_affiliation edges, got %s (%s)", e.Type, e.Classify())
			}
		}
	}

	// 3. Traverse with Classification = "high_confidence_org_link"
	subTechOnly, err := TraverseBFSOpt(g, "github.com", TraversalOptions{
		MaxDepth:       2,
		Classification: ClassHighConfidenceOrgLink,
	})
	if err != nil {
		t.Fatalf("traversal with --classification=high_confidence_org_link failed: %v", err)
	}

	for _, e := range subTechOnly.Edges {
		if strings.HasPrefix(e.SourceID, "domain:") && strings.HasPrefix(e.TargetID, "domain:") {
			if e.Classify() != ClassHighConfidenceOrgLink {
				t.Errorf("expected only high_confidence_org_link edges, got %s (%s)", e.Type, e.Classify())
			}
		}
	}

	t.Logf("Dual Edge Coexistence PASS:\n  - Tech Edge (high_confidence_org_link): 1 (conf=0.88)\n  - Corp Edge (corporate_affiliation):   1 (conf=0.92)\n  - Weak Colocation Pruned by --org-only: Successfully eliminated stranger-cdn.com\n  - Classification Routing: corporate_affiliation and high_confidence_org_link filter independently without crosstalk")
}

func TestMidBranch070PrunedByOrgOnly(t *testing.T) {
	g := NewGraph()

	g.AddNode(&Node{ID: "domain:root.com", Type: NodeDomain, Label: "root.com"})
	g.AddNode(&Node{ID: "domain:generic-collision.com", Type: NodeDomain, Label: "generic-collision.com"})

	// Mid-branch edge: 0.70 confidence
	midBranchEdge := &Edge{
		ID:         "corr:root.com:generic-collision.com:apex",
		SourceID:   "domain:root.com",
		TargetID:   "domain:generic-collision.com",
		Type:       EdgeCorporateAffiliation,
		Confidence: 0.70,
	}
	midBranchEdge.Classification = midBranchEdge.Classify()
	g.AddEdge(midBranchEdge)

	// 1. Verify classification is ClassWeakColocation (not ClassCorporateAffiliation and not ClassHighConfidenceOrgLink)
	if midBranchEdge.Classification != ClassWeakColocation {
		t.Errorf("expected 0.70 edge classification to be %s, got %s", ClassWeakColocation, midBranchEdge.Classification)
	}

	// 2. Traversal with --org-only must prune this edge
	subOrgOnly, err := TraverseBFSOpt(g, "root.com", TraversalOptions{
		MaxDepth:     2,
		OnlyOrgLinks: true,
	})
	if err != nil {
		t.Fatalf("traversal failed: %v", err)
	}

	if _, exists := subOrgOnly.Nodes["domain:generic-collision.com"]; exists {
		t.Errorf("VIOLATION: generic-collision.com (conf=0.70) must be pruned by --org-only")
	}

	t.Logf("Mid-Branch (0.70) Graph Pruning PASS: Edge with conf=0.70 classified as %s and successfully pruned by --org-only",
		midBranchEdge.Classification)
}




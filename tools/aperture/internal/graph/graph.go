package graph

import (
	"time"
)

// NodeType represents the categorical classification of an attack surface node.
type NodeType string

const (
	NodeDomain      NodeType = "domain"
	NodeAsset       NodeType = "asset"
	NodeIP          NodeType = "ip"
	NodeASN         NodeType = "asn"
	NodeSubnet      NodeType = "subnet"
	NodeCertificate NodeType = "certificate"
)

// EdgeType represents the directional relationship between two nodes.
type EdgeType string

const (
	EdgeSubdomainOf  EdgeType = "SUBDOMAIN_OF"
	EdgeResolvesTo   EdgeType = "RESOLVES_TO"
	EdgeAnnouncedBy  EdgeType = "ANNOUNCED_BY"
	EdgePartOfSubnet EdgeType = "PART_OF_SUBNET"
	EdgeSharesSubnet EdgeType = "SHARES_SUBNET"
	EdgeSharesASN            EdgeType = "SHARES_ASN"
	EdgeIssuedWith           EdgeType = "ISSUED_WITH"
	EdgeHostedOn             EdgeType = "HOSTED_ON"
	EdgeCorporateAffiliation EdgeType = "CORPORATE_AFFILIATION"
)

// Node represents a vertex in the attack surface graph.
type Node struct {
	ID        string         `json:"id"`
	Type      NodeType       `json:"type"`
	Label     string         `json:"label"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// EdgeClassification categorizes edges into high-confidence organizational links vs weak infrastructure co-location.
type EdgeClassification string

const (
	ClassHighConfidenceOrgLink EdgeClassification = "high_confidence_org_link" // بنية تحتية
	ClassWeakColocation        EdgeClassification = "weak_colocation"
	ClassStructural            EdgeClassification = "structural"
	ClassCorporateAffiliation  EdgeClassification = "corporate_affiliation" // جديد — WHOIS/registry فقط
)

// Edge represents a directed or correlation relationship between two graph nodes.
type Edge struct {
	ID             string             `json:"id"`
	SourceID       string             `json:"source_id"`
	TargetID       string             `json:"target_id"`
	Type           EdgeType           `json:"type"`
	Confidence     float64            `json:"confidence"`
	Classification EdgeClassification `json:"classification"`
	Metadata       map[string]any     `json:"metadata,omitempty"`
	DiscoveredAt   time.Time          `json:"discovered_at"`
}

// Classify returns the explicit classification or derives it based on type and confidence.
func (e *Edge) Classify() EdgeClassification {
	if e.Classification != "" {
		return e.Classification
	}
	if e.Type == EdgeSubdomainOf || e.Type == EdgeResolvesTo || e.Type == EdgeAnnouncedBy || e.Type == EdgePartOfSubnet || e.Type == EdgeHostedOn {
		return ClassStructural
	}
	if e.Type == EdgeCorporateAffiliation {
		if e.Confidence >= 0.80 {
			return ClassCorporateAffiliation
		}
		return ClassWeakColocation
	}
	if e.Type == EdgeIssuedWith || e.Confidence >= 0.80 {
		return ClassHighConfidenceOrgLink
	}
	return ClassWeakColocation
}

// Graph holds an attack surface graph in memory.
type Graph struct {
	Nodes map[string]*Node `json:"nodes"`
	Edges map[string]*Edge `json:"edges"`

	// Adjacency list for fast BFS/DFS traversal (undirected search for correlations)
	Adjacency map[string][]string `json:"-"`

	// IncidentEdges maps each node ID to its incident edges for classification-aware routing
	IncidentEdges map[string][]*Edge `json:"-"`
}

// NewGraph initializes an empty graph.
func NewGraph() *Graph {
	return &Graph{
		Nodes:         make(map[string]*Node),
		Edges:         make(map[string]*Edge),
		Adjacency:     make(map[string][]string),
		IncidentEdges: make(map[string][]*Edge),
	}
}

// AddNode registers a node in the graph.
func (g *Graph) AddNode(n *Node) {
	if n == nil || n.ID == "" {
		return
	}
	g.Nodes[n.ID] = n
	if _, ok := g.Adjacency[n.ID]; !ok {
		g.Adjacency[n.ID] = []string{}
	}
	if _, ok := g.IncidentEdges[n.ID]; !ok {
		g.IncidentEdges[n.ID] = []*Edge{}
	}
}

// AddEdge registers an edge and updates the adjacency graph.
func (g *Graph) AddEdge(e *Edge) {
	if e == nil || e.ID == "" {
		return
	}
	g.Edges[e.ID] = e
	g.Adjacency[e.SourceID] = append(g.Adjacency[e.SourceID], e.TargetID)
	g.Adjacency[e.TargetID] = append(g.Adjacency[e.TargetID], e.SourceID) // Bi-directional navigation
	g.IncidentEdges[e.SourceID] = append(g.IncidentEdges[e.SourceID], e)
	g.IncidentEdges[e.TargetID] = append(g.IncidentEdges[e.TargetID], e)
}

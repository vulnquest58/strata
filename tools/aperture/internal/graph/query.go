package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SubGraph represents a traversal slice of the attack surface graph.
type SubGraph struct {
	RootNodeID string           `json:"root_node_id"`
	MaxDepth   int              `json:"max_depth"`
	Nodes      map[string]*Node `json:"nodes"`
	Edges      map[string]*Edge `json:"edges"`
}

// TraversalOptions defines controls for scoping attack surface graph exploration.
type TraversalOptions struct {
	MaxDepth       int
	MinConfidence  float64
	Classification EdgeClassification // filter cross-target edges by classification
	OnlyOrgLinks   bool               // strictly traverse high_confidence_org_link correlations
}

// TraverseBFS traverses the graph starting from rootIdentifier up to maxDepth hops with default options.
func TraverseBFS(g *Graph, rootIdentifier string, maxDepth int) (*SubGraph, error) {
	return TraverseBFSOpt(g, rootIdentifier, TraversalOptions{
		MaxDepth: maxDepth,
	})
}

// TraverseBFSOpt traverses the graph starting from rootIdentifier with advanced classification and confidence options.
func TraverseBFSOpt(g *Graph, rootIdentifier string, opts TraversalOptions) (*SubGraph, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is nil")
	}

	// 1. Locate start node
	startNodeID := ""
	if _, ok := g.Nodes[rootIdentifier]; ok {
		startNodeID = rootIdentifier
	} else if _, ok := g.Nodes["domain:"+rootIdentifier]; ok {
		startNodeID = "domain:" + rootIdentifier
	} else if _, ok := g.Nodes["asset:"+rootIdentifier]; ok {
		startNodeID = "asset:" + rootIdentifier
	} else {
		// Search by label
		for _, n := range g.Nodes {
			if strings.EqualFold(n.Label, rootIdentifier) {
				startNodeID = n.ID
				break
			}
		}
	}

	if startNodeID == "" {
		return nil, fmt.Errorf("start node %q not found in graph", rootIdentifier)
	}

	sub := &SubGraph{
		RootNodeID: startNodeID,
		MaxDepth:   opts.MaxDepth,
		Nodes:      make(map[string]*Node),
		Edges:      make(map[string]*Edge),
	}

	type queueItem struct {
		nodeID string
		depth  int
	}

	queue := []queueItem{{nodeID: startNodeID, depth: 0}}
	visited := map[string]int{startNodeID: 0}
	sub.Nodes[startNodeID] = g.Nodes[startNodeID]

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.depth >= opts.MaxDepth {
			continue
		}

		incident := g.IncidentEdges[curr.nodeID]
		for _, e := range incident {
			// Confidence filtering
			if opts.MinConfidence > 0 && e.Confidence < opts.MinConfidence {
				continue
			}

			// Classification-based routing
			class := e.Classify()
			if opts.OnlyOrgLinks && class == ClassWeakColocation {
				continue
			}
			if opts.Classification != "" && class != opts.Classification && class != ClassStructural {
				continue
			}

			neighborID := e.SourceID
			if neighborID == curr.nodeID {
				neighborID = e.TargetID
			}

			if d, seen := visited[neighborID]; !seen || curr.depth+1 < d {
				visited[neighborID] = curr.depth + 1
				sub.Nodes[neighborID] = g.Nodes[neighborID]
				queue = append(queue, queueItem{nodeID: neighborID, depth: curr.depth + 1})
			}
		}
	}

	// Collect edges where both endpoints are in the visited subgraph and meet filters
	for _, edge := range g.Edges {
		_, srcIn := sub.Nodes[edge.SourceID]
		_, tgtIn := sub.Nodes[edge.TargetID]
		if srcIn && tgtIn {
			if opts.MinConfidence > 0 && edge.Confidence < opts.MinConfidence {
				continue
			}
			class := edge.Classify()
			if opts.OnlyOrgLinks && class == ClassWeakColocation {
				continue
			}
			if opts.Classification != "" && class != opts.Classification && class != ClassStructural {
				continue
			}
			sub.Edges[edge.ID] = edge
		}
	}

	return sub, nil
}

// ExportJSON serializes the SubGraph into formatted JSON.
func (sg *SubGraph) ExportJSON() ([]byte, error) {
	type outputGraph struct {
		RootNodeID string  `json:"root_node_id"`
		MaxDepth   int     `json:"max_depth"`
		NodeCount  int     `json:"node_count"`
		EdgeCount  int     `json:"edge_count"`
		Nodes      []*Node `json:"nodes"`
		Edges      []*Edge `json:"edges"`
	}

	nodes := make([]*Node, 0, len(sg.Nodes))
	for _, n := range sg.Nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	edges := make([]*Edge, 0, len(sg.Edges))
	for _, e := range sg.Edges {
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })

	out := outputGraph{
		RootNodeID: sg.RootNodeID,
		MaxDepth:   sg.MaxDepth,
		NodeCount:  len(nodes),
		EdgeCount:  len(edges),
		Nodes:      nodes,
		Edges:      edges,
	}

	return json.MarshalIndent(out, "", "  ")
}

// ExportDOT renders the SubGraph into Graphviz DOT language format.
func (sg *SubGraph) ExportDOT() string {
	var sb strings.Builder
	sb.WriteString("digraph AttackSurface {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  bgcolor=\"#1e1e2e\";\n")
	sb.WriteString("  node [fontname=\"Helvetica\", fontsize=10, style=\"filled,rounded\", fontcolor=\"#ffffff\"];\n")
	sb.WriteString("  edge [fontname=\"Helvetica\", fontsize=8, fontcolor=\"#cdd6f4\"];\n\n")

	// Helper for safe DOT node IDs
	dotID := func(rawID string) string {
		clean := strings.ReplaceAll(rawID, ":", "_")
		clean = strings.ReplaceAll(clean, ".", "_")
		clean = strings.ReplaceAll(clean, "-", "_")
		clean = strings.ReplaceAll(clean, "/", "_")
		return "\"" + clean + "\""
	}

	// Render Nodes
	for _, n := range sg.Nodes {
		fillColor := "#45475a"
		shape := "box"

		switch n.Type {
		case NodeDomain:
			fillColor = "#89b4fa" // soft blue
			shape = "component"
		case NodeAsset:
			fillColor = "#a6e3a1" // soft green
			shape = "box"
		case NodeIP:
			fillColor = "#f9e2af" // soft yellow
			shape = "ellipse"
		case NodeASN:
			fillColor = "#fab387" // soft orange
			shape = "hexagon"
		case NodeSubnet:
			fillColor = "#cba6f7" // soft purple
			shape = "parallelogram"
		}

		fontColor := "#11111b"
		sb.WriteString(fmt.Sprintf("  %s [label=\"%s\\n(%s)\", shape=%s, fillcolor=\"%s\", fontcolor=\"%s\"];\n",
			dotID(n.ID), n.Label, n.Type, shape, fillColor, fontColor))
	}

	sb.WriteString("\n")

	// Render Edges
	for _, e := range sg.Edges {
		edgeColor := "#6c7086"
		penWidth := "1.0"
		style := "solid"

		class := e.Classify()
		label := fmt.Sprintf("%s (%.2f)", e.Type, e.Confidence)

		switch class {
		case ClassHighConfidenceOrgLink:
			edgeColor = "#f38ba8" // bold coral for confirmed organizational link
			penWidth = "2.5"
			style = "solid"
			label = fmt.Sprintf("[ORG LINK] %s (%.2f)", e.Type, e.Confidence)
		case ClassCorporateAffiliation:
			edgeColor = "#cba6f7" // distinct vibrant lavender for non-infrastructure registry corporate affiliation
			penWidth = "2.2"
			style = "dashed"
			label = fmt.Sprintf("[CORP AFFILIATION] %s (%.2f)", e.Type, e.Confidence)
		case ClassWeakColocation:
			edgeColor = "#fab387" // muted amber for weak co-location
			penWidth = "1.5"
			style = "dashed"
			label = fmt.Sprintf("[CO-LOC] %s (%.2f)", e.Type, e.Confidence)
		case ClassStructural:
			if e.Confidence == 1.0 {
				label = string(e.Type)
			}
		}

		sb.WriteString(fmt.Sprintf("  %s -> %s [label=\"%s\", color=\"%s\", penwidth=%s, style=\"%s\"];\n",
			dotID(e.SourceID), dotID(e.TargetID), label, edgeColor, penWidth, style))
	}

	sb.WriteString("}\n")
	return sb.String()
}

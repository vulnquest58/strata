package graph

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"aperture/internal/store"
)

// Builder constructs unified attack surface graphs from Aperture store entities.
type Builder struct {
	store         store.Store
	minConfidence float64
}

// NewBuilder creates a new graph builder with a default minimum correlation confidence of 0.60.
func NewBuilder(s store.Store) *Builder {
	return &Builder{
		store:         s,
		minConfidence: 0.60,
	}
}

// SetMinConfidence configures the minimum correlation confidence threshold.
func (b *Builder) SetMinConfidence(minConf float64) {
	b.minConfidence = minConf
}

// Build constructs an in-memory Graph from all stored fingerprints and correlations.
func (b *Builder) Build(ctx context.Context) (*Graph, error) {
	g := NewGraph()

	// 1. Retrieve all fingerprints
	fps, err := b.store.GetFingerprints(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("fetching fingerprints for graph: %w", err)
	}

	for _, fp := range fps {
		now := time.Now().UTC()

		// Domain node
		domainNodeID := "domain:" + fp.RootDomain
		if _, exists := g.Nodes[domainNodeID]; !exists {
			g.AddNode(&Node{
				ID:        domainNodeID,
				Type:      NodeDomain,
				Label:     fp.RootDomain,
				CreatedAt: now,
			})
		}

		// Asset node
		assetNodeID := "asset:" + fp.AssetID
		g.AddNode(&Node{
			ID:        assetNodeID,
			Type:      NodeAsset,
			Label:     fp.AssetID,
			CreatedAt: fp.ExtractedAt,
			Metadata: map[string]any{
				"root_domain":   fp.RootDomain,
				"cdn_providers": fp.CDNProviders,
			},
		})

		// Edge: asset -> domain (SUBDOMAIN_OF)
		g.AddEdge(&Edge{
			ID:             fmt.Sprintf("edge:%s:subdomain:%s", assetNodeID, domainNodeID),
			SourceID:       assetNodeID,
			TargetID:       domainNodeID,
			Type:           EdgeSubdomainOf,
			Confidence:     1.0,
			Classification: ClassStructural,
			Metadata:       map[string]any{"classification": string(ClassStructural)},
			DiscoveredAt:   fp.ExtractedAt,
		})

		// IP nodes and connections
		for _, ip := range fp.ResolvedIPs {
			ipNodeID := "ip:" + ip
			if _, exists := g.Nodes[ipNodeID]; !exists {
				g.AddNode(&Node{
					ID:        ipNodeID,
					Type:      NodeIP,
					Label:     ip,
					CreatedAt: now,
				})
			}

			// Edge: asset -> ip (RESOLVES_TO)
			g.AddEdge(&Edge{
				ID:             fmt.Sprintf("edge:%s:resolves:%s", assetNodeID, ipNodeID),
				SourceID:       assetNodeID,
				TargetID:       ipNodeID,
				Type:           EdgeResolvesTo,
				Confidence:     1.0,
				Classification: ClassStructural,
				Metadata:       map[string]any{"classification": string(ClassStructural)},
				DiscoveredAt:   fp.ExtractedAt,
			})

			// ASN Node and Edge
			if fp.ASN > 0 {
				asnNodeID := fmt.Sprintf("asn:AS%d", fp.ASN)
				if _, exists := g.Nodes[asnNodeID]; !exists {
					label := fmt.Sprintf("AS%d", fp.ASN)
					if fp.ASOrg != "" {
						label = fmt.Sprintf("AS%d (%s)", fp.ASN, fp.ASOrg)
					}
					g.AddNode(&Node{
						ID:        asnNodeID,
						Type:      NodeASN,
						Label:     label,
						CreatedAt: now,
						Metadata: map[string]any{
							"asn":    fp.ASN,
							"as_org": fp.ASOrg,
						},
					})
				}

				// Edge: ip -> asn (ANNOUNCED_BY)
				g.AddEdge(&Edge{
					ID:             fmt.Sprintf("edge:%s:announced_by:%s", ipNodeID, asnNodeID),
					SourceID:       ipNodeID,
					TargetID:       asnNodeID,
					Type:           EdgeAnnouncedBy,
					Confidence:     1.0,
					Classification: ClassStructural,
					Metadata:       map[string]any{"classification": string(ClassStructural)},
					DiscoveredAt:   fp.ExtractedAt,
				})

				// Edge: asset -> asn (HOSTED_ON) - ensures ASN is reachable at depth 2 from root domain
				g.AddEdge(&Edge{
					ID:             fmt.Sprintf("edge:%s:hosted_on:%s", assetNodeID, asnNodeID),
					SourceID:       assetNodeID,
					TargetID:       asnNodeID,
					Type:           EdgeHostedOn,
					Confidence:     1.0,
					Classification: ClassStructural,
					Metadata:       map[string]any{"classification": string(ClassStructural)},
					DiscoveredAt:   fp.ExtractedAt,
				})
			}

			// Subnet Node and Edge
			for _, subnet := range fp.IPRanges24 {
				subnetNodeID := "subnet:" + subnet
				if _, exists := g.Nodes[subnetNodeID]; !exists {
					g.AddNode(&Node{
						ID:        subnetNodeID,
						Type:      NodeSubnet,
						Label:     subnet,
						CreatedAt: now,
					})
				}

				// Edge: ip -> subnet (PART_OF_SUBNET)
				g.AddEdge(&Edge{
					ID:             fmt.Sprintf("edge:%s:part_of:%s", ipNodeID, subnetNodeID),
					SourceID:       ipNodeID,
					TargetID:       subnetNodeID,
					Type:           EdgePartOfSubnet,
					Confidence:     1.0,
					Classification: ClassStructural,
					Metadata:       map[string]any{"classification": string(ClassStructural)},
					DiscoveredAt:   fp.ExtractedAt,
				})

				// Edge: asset -> subnet (PART_OF_SUBNET) - ensures Subnet is reachable at depth 2 from root domain
				g.AddEdge(&Edge{
					ID:             fmt.Sprintf("edge:%s:part_of_subnet:%s", assetNodeID, subnetNodeID),
					SourceID:       assetNodeID,
					TargetID:       subnetNodeID,
					Type:           EdgePartOfSubnet,
					Confidence:     1.0,
					Classification: ClassStructural,
					Metadata:       map[string]any{"classification": string(ClassStructural)},
					DiscoveredAt:   fp.ExtractedAt,
				})
			}
		}
	}

	// 2. Retrieve and incorporate cross-target correlations
	corrs, err := b.store.ListCorrelations(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("fetching correlations for graph: %w", err)
	}

	for _, c := range corrs {
		// Filter out weak / low-confidence correlations (e.g. below 0.60)
		if c.Confidence < b.minConfidence {
			continue
		}

		domainAID := "domain:" + c.RootDomainA
		domainBID := "domain:" + c.RootDomainB

		// Ensure domain nodes exist
		if _, ok := g.Nodes[domainAID]; !ok {
			g.AddNode(&Node{ID: domainAID, Type: NodeDomain, Label: c.RootDomainA, CreatedAt: c.DiscoveredAt})
		}
		if _, ok := g.Nodes[domainBID]; !ok {
			g.AddNode(&Node{ID: domainBID, Type: NodeDomain, Label: c.RootDomainB, CreatedAt: c.DiscoveredAt})
		}

		edgeType := EdgeSharesSubnet
		if c.CorrelationType == "shared_cert_san" {
			edgeType = EdgeIssuedWith
		} else if strings.Contains(strings.ToLower(c.CorrelationType), "asn") {
			edgeType = EdgeSharesASN
		} else if c.CorrelationType == "corporate_affiliation" {
			edgeType = EdgeCorporateAffiliation
		}

		// Edge classification: High confidence organizational link vs weak co-location vs corporate affiliation
		classification := ClassWeakColocation
		if c.CorrelationType == "corporate_affiliation" {
			if c.Confidence >= 0.80 {
				classification = ClassCorporateAffiliation
			} else {
				classification = ClassWeakColocation
			}
		} else if c.CorrelationType == "shared_cert_san" || c.Confidence >= 0.80 {
			classification = ClassHighConfidenceOrgLink
		}
		edgeMeta := map[string]any{
			"classification":   string(classification),
			"correlation_type": c.CorrelationType,
			"evidence":         c.Evidence,
			"shared_element":   c.SharedElement,
		}
		if c.CorrelationType == "corporate_affiliation" {
			if mo, ok := c.Evidence["matched_org"].(string); ok && mo != "" {
				edgeMeta["matched_org"] = mo
			} else {
				edgeMeta["matched_org"] = c.SharedElement
			}
		}

		// Edge between domains - keep highest confidence if already seen
		edgeID := fmt.Sprintf("corr:%s:%s:%s", c.RootDomainA, c.RootDomainB, c.SharedElement)
		if existing, ok := g.Edges[edgeID]; ok {
			if c.Confidence > existing.Confidence {
				existing.Confidence = c.Confidence
				existing.Classification = classification
				existing.Metadata = edgeMeta
				existing.DiscoveredAt = c.DiscoveredAt
			}
		} else {
			g.AddEdge(&Edge{
				ID:             edgeID,
				SourceID:       domainAID,
				TargetID:       domainBID,
				Type:           edgeType,
				Confidence:     c.Confidence,
				Classification: classification,
				Metadata:       edgeMeta,
				DiscoveredAt:   c.DiscoveredAt,
			})
		}

		// Also connect respective assets if both exist
		assetAID := "asset:" + c.AssetA
		assetBID := "asset:" + c.AssetB
		if _, okA := g.Nodes[assetAID]; okA {
			if _, okB := g.Nodes[assetBID]; okB {
				assetEdgeID := fmt.Sprintf("corr_asset:%s:%s:%s", c.AssetA, c.AssetB, c.SharedElement)
				if existing, ok := g.Edges[assetEdgeID]; ok {
					if c.Confidence > existing.Confidence {
						existing.Confidence = c.Confidence
						existing.Classification = classification
						existing.Metadata = edgeMeta
						existing.DiscoveredAt = c.DiscoveredAt
					}
				} else {
					g.AddEdge(&Edge{
						ID:             assetEdgeID,
						SourceID:       assetAID,
						TargetID:       assetBID,
						Type:           edgeType,
						Confidence:     c.Confidence,
						Classification: classification,
						Metadata:       edgeMeta,
						DiscoveredAt:   c.DiscoveredAt,
					})
				}
			}
		}
	}

	return g, nil
}

// PersistToDB stores the graph nodes and edges into SQLite tables.
func (b *Builder) PersistToDB(ctx context.Context, db *sql.DB, g *Graph) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Insert/Replace nodes
	nodeStmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO graph_nodes (id, node_type, label, metadata, created_at)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer nodeStmt.Close()

	for _, n := range g.Nodes {
		metaJSON, _ := json.Marshal(n.Metadata)
		_, err := nodeStmt.ExecContext(ctx, n.ID, string(n.Type), n.Label, string(metaJSON), n.CreatedAt.UTC().Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("inserting graph node %q: %w", n.ID, err)
		}
	}

	// 2. Insert/Replace edges
	edgeStmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO graph_edges (id, source_id, target_id, edge_type, confidence, metadata, discovered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer edgeStmt.Close()

	for _, e := range g.Edges {
		metaJSON, _ := json.Marshal(e.Metadata)
		_, err := edgeStmt.ExecContext(ctx, e.ID, e.SourceID, e.TargetID, string(e.Type), e.Confidence, string(metaJSON), e.DiscoveredAt.UTC().Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("inserting graph edge %q: %w", e.ID, err)
		}
	}

	return tx.Commit()
}

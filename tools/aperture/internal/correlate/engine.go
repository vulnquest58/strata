package correlate

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	"aperture/internal/model"
	"aperture/internal/store"
)

// Engine orchestrates infrastructure fingerprint extraction and cross-target correlation.
type Engine struct {
	store store.Store
}

// NewEngine creates a new correlation engine.
func NewEngine(s store.Store) *Engine {
	return &Engine{store: s}
}

// ExtractFingerprint constructs an InfrastructureFingerprint from a Finding.
func (e *Engine) ExtractFingerprint(f *model.Finding) *model.InfrastructureFingerprint {
	fp := &model.InfrastructureFingerprint{
		AssetID:      f.AssetID,
		RootDomain:   f.ParentAsset,
		ResolvedIPs:  f.ResolvedIPs,
		ExtractedAt:  time.Now().UTC(),
		CDNProviders: model.DetectCDN(f.ResolvedIPs, f.Metadata),
	}

	// Calculate unique IPv4 /24 subnets
	seenSubnets := make(map[string]bool)
	for _, ip := range f.ResolvedIPs {
		subnet := model.CalculateSubnet24(ip)
		if subnet != "" && !seenSubnets[subnet] {
			seenSubnets[subnet] = true
			fp.IPRanges24 = append(fp.IPRanges24, subnet)
		}
	}

	// Resolve ASN and Org
	seenASNs := make(map[int]bool)
	for _, ip := range f.ResolvedIPs {
		asnNum, asOrg, err := model.LookupASN(ip)
		if err == nil && asnNum > 0 {
			if fp.ASN == 0 {
				fp.ASN = asnNum
				fp.ASOrg = asOrg
			}
			if !seenASNs[asnNum] {
				seenASNs[asnNum] = true
				fp.ASNSet = append(fp.ASNSet, fmt.Sprintf("AS%d", asnNum))
			}
		}
	}

	// Extract certificate details from metadata
	if f.Metadata != nil {
		if issuer, ok := f.Metadata["issuer_name"].(string); ok && issuer != "" {
			fp.CertIssuers = append(fp.CertIssuers, issuer)
		}

		// Check for dns_names / san_list in metadata
		if sans, ok := f.Metadata["san_list"].([]string); ok {
			fp.SANList = sans
		} else if sansAny, ok := f.Metadata["san_list"].([]any); ok {
			for _, s := range sansAny {
				if str, ok := s.(string); ok {
					fp.SANList = append(fp.SANList, str)
				}
			}
		} else if dnsNamesAny, ok := f.Metadata["dns_names"].([]any); ok {
			for _, d := range dnsNamesAny {
				if str, ok := d.(string); ok {
					fp.SANList = append(fp.SANList, str)
				}
			}
		}
	}

	return fp
}

// Correlate compares fingerprints across all stored root domains to detect shared infrastructure.
// Returns newly discovered or updated correlations.
func (e *Engine) Correlate(ctx context.Context, targetRootDomain string) ([]*model.CrossTargetCorrelation, error) {
	allFPs, err := e.store.GetFingerprints(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("retrieving fingerprints: %w", err)
	}

	if len(allFPs) < 2 {
		return nil, nil
	}

	// Enrich any fingerprints missing ASN
	for _, fp := range allFPs {
		if fp.ASN == 0 && len(fp.ResolvedIPs) > 0 {
			for _, ip := range fp.ResolvedIPs {
				asnNum, asOrg, err := model.LookupASN(ip)
				if err == nil && asnNum > 0 {
					fp.ASN = asnNum
					fp.ASOrg = asOrg
					fp.ASNSet = append(fp.ASNSet, fmt.Sprintf("AS%d", asnNum))
					_ = e.store.SaveFingerprint(ctx, fp)
					break
				}
			}
		}
	}

	// Group fingerprints by RootDomain
	byDomain := make(map[string][]*model.InfrastructureFingerprint)
	for _, fp := range allFPs {
		byDomain[fp.RootDomain] = append(byDomain[fp.RootDomain], fp)
	}

	if len(byDomain) < 2 {
		return nil, nil // Only one root domain observed so far
	}

	var newCorrelations []*model.CrossTargetCorrelation
	seenPairs := make(map[string]bool)

	domains := make([]string, 0, len(byDomain))
	for d := range byDomain {
		domains = append(domains, d)
	}

	for i := 0; i < len(domains); i++ {
		for j := i + 1; j < len(domains); j++ {
			domA := domains[i]
			domB := domains[j]

			// If targetRootDomain is given, at least one domain must match
			if targetRootDomain != "" && domA != targetRootDomain && domB != targetRootDomain {
				continue
			}

			listA := byDomain[domA]
			listB := byDomain[domB]

			for _, fpA := range listA {
				for _, fpB := range listB {
					// 1. Check TLS SAN Overlap
					if sanOverlap, match := checkSANOverlap(fpA, fpB); match {
						pairKey := fmt.Sprintf("san:%s:%s:%s", domA, domB, sanOverlap)
						if !seenPairs[pairKey] {
							seenPairs[pairKey] = true
							corr := &model.CrossTargetCorrelation{
								ID:              uuid.NewString(),
								RootDomainA:     domA,
								RootDomainB:     domB,
								AssetA:          fpA.AssetID,
								AssetB:          fpB.AssetID,
								CorrelationType: "shared_cert_san",
								SharedElement:   sanOverlap,
								Confidence:      0.95, // Common administrative control required for multi-domain SAN
								Evidence: map[string]any{
									"san_match": sanOverlap,
									"source":    "tls_san_inspection",
								},
								DiscoveredAt: time.Now().UTC(),
							}
							if err := e.store.SaveCorrelation(ctx, corr); err == nil {
								newCorrelations = append(newCorrelations, corr)
							}
						}
					}

					// 2. Check /24 Subnet Overlap (with Weighted Context Confidence)
					if isSharedSubnet, subnet := checkSubnetOverlap(fpA, fpB); isSharedSubnet {
						pairKey := fmt.Sprintf("subnet:%s:%s:%s", domA, domB, subnet)
						if !seenPairs[pairKey] {
							seenPairs[pairKey] = true

							// Contextual adjustments
							sharedASN := (fpA.ASN != 0 && fpA.ASN == fpB.ASN)
							isPublicCDN := model.IsPublicCDN(fpA.CDNProviders, fpA.ASOrg) || model.IsPublicCDN(fpB.CDNProviders, fpB.ASOrg)
							namingSim := NamingSimilarity(domA, domB)
							conf := WeightedConfidence(0.70, sharedASN, isPublicCDN, namingSim)

							corr := &model.CrossTargetCorrelation{
								ID:              uuid.NewString(),
								RootDomainA:     domA,
								RootDomainB:     domB,
								AssetA:          fpA.AssetID,
								AssetB:          fpB.AssetID,
								CorrelationType: "shared_subnet_24",
								SharedElement:   subnet,
								Confidence:      math.Round(conf*100) / 100,
								Evidence: map[string]any{
									"subnet_24":         subnet,
									"source":            "ip_neighborhood_clustering",
									"shared_asn":        sharedASN,
									"is_public_cdn":     isPublicCDN,
									"naming_similarity": math.Round(namingSim*100) / 100,
								},
								DiscoveredAt: time.Now().UTC(),
							}
							if err := e.store.SaveCorrelation(ctx, corr); err == nil {
								newCorrelations = append(newCorrelations, corr)
							}
						}
					}
				}
			}
		}
	}

	return newCorrelations, nil
}

// checkSANOverlap detects whether fpA and fpB share SAN entries or cross-reference each other's root domain.
func checkSANOverlap(fpA, fpB *model.InfrastructureFingerprint) (string, bool) {
	// A) Did fpA's certificate include fpB's root domain?
	for _, san := range fpA.SANList {
		sanLower := strings.ToLower(san)
		if strings.HasSuffix(sanLower, "."+fpB.RootDomain) || sanLower == fpB.RootDomain {
			return san, true
		}
	}

	// B) Did fpB's certificate include fpA's root domain?
	for _, san := range fpB.SANList {
		sanLower := strings.ToLower(san)
		if strings.HasSuffix(sanLower, "."+fpA.RootDomain) || sanLower == fpA.RootDomain {
			return san, true
		}
	}

	// C) Exact SAN match between both
	setA := make(map[string]bool)
	for _, s := range fpA.SANList {
		setA[strings.ToLower(s)] = true
	}
	for _, s := range fpB.SANList {
		sLower := strings.ToLower(s)
		if setA[sLower] && !strings.HasPrefix(sLower, "*") {
			return s, true
		}
	}

	return "", false
}

// checkSubnetOverlap checks if both assets share a non-generic /24 subnet.
func checkSubnetOverlap(fpA, fpB *model.InfrastructureFingerprint) (bool, string) {
	setA := make(map[string]bool)
	for _, s := range fpA.IPRanges24 {
		setA[s] = true
	}
	for _, s := range fpB.IPRanges24 {
		if setA[s] {
			return true, s
		}
	}
	return false, ""
}

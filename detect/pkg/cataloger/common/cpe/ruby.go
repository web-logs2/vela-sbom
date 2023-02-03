package cpe

import "github.com/vela-ssoc/vela-sbom/detect/pkg"

func candidateVendorsForRuby(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.GemMetadata)
	if !ok {
		return nil
	}

	vendors := newFieldCandidateSet()

	for _, author := range metadata.Authors {
		// author could be a name or an email
		vendors.add(fieldCandidate{
			value:                 normalizePersonName(stripEmailSuffix(author)),
			disallowSubSelections: true,
		})
	}
	return vendors
}
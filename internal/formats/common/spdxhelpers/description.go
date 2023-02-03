package spdxhelpers

import "github.com/vela-ssoc/vela-sbom/detect/pkg"

func Description(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkMetadata:
			return metadata.Description
		case pkg.NpmPackageJSONMetadata:
			return metadata.Description
		}
	}
	return ""
}

func hasMetadata(p pkg.Package) bool {
	return p.Metadata != nil
}

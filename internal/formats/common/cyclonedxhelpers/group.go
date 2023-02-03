package cyclonedxhelpers

import "github.com/vela-ssoc/vela-sbom/detect/pkg"

func encodeGroup(p pkg.Package) string {
	if hasMetadata(p) {
		if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok && metadata.PomProperties != nil {
			return metadata.PomProperties.GroupID
		}
	}
	return ""
}

func decodeGroup(group string, metadata interface{}) {
	if meta, ok := metadata.(*pkg.JavaMetadata); ok {
		if meta.PomProperties == nil {
			meta.PomProperties = &pkg.PomProperties{}
		}
		meta.PomProperties.GroupID = group
	}
}

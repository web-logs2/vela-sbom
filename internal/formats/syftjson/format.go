package syftjson

import (
	"github.com/vela-ssoc/vela-sbom/detect/sbom"
)

const ID sbom.FormatID = "syft-3-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		encoder,
		decoder,
		validator,
	)
}

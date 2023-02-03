/*
Package syft is a "one-stop-shop" for helper utilities for all major functionality provided by child packages of the syft library.

Here is what the main execution path for syft does:

	1. Parse a user image string to get a stereoscope image.Source object
	2. Invoke all catalogers to catalog the image, adding discovered packages to a single catalog object
	3. Invoke one or more encoders to output contents of the catalog

A Source object encapsulates the image object to be cataloged and the user options (catalog all layers vs. squashed layer),
providing a way to inspect paths and file content within the image. The Source object, not the image object, is used
throughout the main execution path. This abstraction allows for decoupling of what is cataloged (a docker image, an OCI
image, a filesystem, etc) and how it is cataloged (the individual catalogers).

Similar to the cataloging process, Linux distribution identification is also performed based on what is discovered within the image.
*/
package detect

import (
	"fmt"
	"github.com/vela-ssoc/vela-sbom/detect/artifact"

	"github.com/vela-ssoc/vela-sbom/detect/linux"
	"github.com/vela-ssoc/vela-sbom/detect/pkg"
	"github.com/vela-ssoc/vela-sbom/detect/pkg/cataloger"
	"github.com/vela-ssoc/vela-sbom/detect/source"
	"github.com/vela-ssoc/vela-sbom/internal/log"
)

// CatalogPackages takes an inventory of packages from the given image from a particular perspective
// (e.g. squashed source, all-layers source). Returns the discovered  set of packages, the identified Linux
// distribution, and the source object used to wrap the data source.
func CatalogPackages(src *source.Source, cfg cataloger.Config) (*pkg.Catalog, []artifact.Relationship, *linux.Release, error) {
	resolver, err := src.FileResolver(cfg.Search.Scope)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to determine resolver while cataloging packages: %w", err)
	}

	// find the distro
	release := linux.IdentifyRelease(resolver)
	if release != nil {
		log.Infof("identified distro: %s", release.String())
	} else {
		log.Info("could not identify distro")
	}

	// conditionally use the correct set of loggers based on the input type (container image or directory)
	var catalogers []cataloger.Cataloger
	switch src.Metadata.Scheme {
	case source.ImageScheme:
		log.Info("cataloging image")
		catalogers = cataloger.ImageCatalogers(cfg)
	case source.FileScheme:
		log.Info("cataloging file")
		catalogers = cataloger.AllCatalogers(cfg)
	case source.DirectoryScheme:
		log.Info("cataloging directory")
		catalogers = cataloger.DirectoryCatalogers(cfg)
	default:
		return nil, nil, nil, fmt.Errorf("unable to determine cataloger set from scheme=%+v", src.Metadata.Scheme)
	}

	if cataloger.RequestedAllCatalogers(cfg) {
		catalogers = cataloger.AllCatalogers(cfg)
	}

	catalog, relationships, err := cataloger.Catalog(resolver, release, catalogers...)
	if err != nil {
		return nil, nil, nil, err
	}

	return catalog, relationships, release, nil
}

// Package capture validates and seals captured native evidence.
package capture

import (
	"context"
	"errors"
	"fmt"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/internal/dependency"
)

type Diagnostics struct{ Failed, Incomplete fm.Diagnostic }

// Graph never trusts a parser to substitute capture identity, source, or completeness.
// Failure text is returned to the caller; only fixed diagnostics enter the graph.
func Graph(ctx context.Context, parser config.Parser, source config.Source, metadata fm.Metadata, prior error, invalid error, diagnostics Diagnostics) (*fm.Firewall, error) {
	if len(source.Text) > config.DefaultMaxBytes {
		return nil, errors.Join(prior, invalid, fmt.Errorf("capture exceeds parser limit"))
	}
	failure := errors.Join(prior, ctx.Err())
	if dependency.Nil(parser) {
		failure = errors.Join(failure, invalid)
	}
	var fw *fm.Firewall
	if failure == nil {
		fw, failure = parser.Parse(ctx, source, metadata)
		failure = errors.Join(failure, ctx.Err())
	}
	if failure == nil && (fw == nil || !sameMetadata(fw.Metadata(), metadata) || fw.Raw() != source.Text) {
		failure = fmt.Errorf("%w: parser did not retain captured identity and source", invalid)
	}
	if failure != nil {
		metadata.SourceDigest, metadata.ParserVersion = "", ""
		incomplete, err := fm.Seal(fm.Data{Metadata: metadata, Raw: source.Text, Diagnostics: []fm.Diagnostic{diagnostics.Failed}})
		return incomplete, errors.Join(failure, err)
	}
	if !source.Complete && fw.Complete() {
		d := fw.Export()
		d.Diagnostics = append(d.Diagnostics, diagnostics.Incomplete)
		return fm.Seal(d)
	}
	return fw, nil
}
func sameMetadata(a, b fm.Metadata) bool {
	return a.Device == b.Device && a.Vendor == b.Vendor && a.Context == b.Context && a.Software == b.Software && a.CapturedAt.Equal(b.CapturedAt)
}

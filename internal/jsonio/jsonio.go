// Package jsonio provides bounded JSON I/O without application-level validation.
package jsonio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

// ErrLimit means the input or encoded output exceeds the byte limit.
var ErrLimit = errors.New("jsonio: byte limit exceeded")

// ErrTrailing means data follows the first JSON value.
var ErrTrailing = errors.New("jsonio: trailing data")

// Read consumes at most limit+1 bytes and returns data only on success.
// Callers validate r and own interruption of an individual blocking Read.
func Read(ctx context.Context, r io.Reader, limit int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(&reader{ctx: ctx, src: r}, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, ErrLimit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}

// reader belongs to one Read call and borrows its source without closing it.
type reader struct {
	ctx   context.Context
	src   io.Reader
	empty int
}

func (r *reader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.src.Read(p)
	if n == 0 && err == nil {
		r.empty++
		const maxEmptyReads = 100
		if r.empty >= maxEmptyReads {
			return 0, io.ErrNoProgress
		}
	} else {
		r.empty = 0
	}
	return n, err
}

// Decode accepts one JSON value, rejecting unknown fields and trailing data.
func Decode(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrTrailing
	}
	return nil
}

// Encode includes the JSON encoder's trailing newline in the byte limit.
// No bytes are returned on failure or cancellation.
func Encode(ctx context.Context, value any, limit int) ([]byte, error) {
	b := buffer{limit: limit, ctx: ctx}
	if err := json.NewEncoder(&b).Encode(value); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

type buffer struct {
	bytes.Buffer
	limit int
	ctx   context.Context
}

func (b *buffer) Write(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > b.limit-b.Len() {
		return 0, ErrLimit
	}
	return b.Buffer.Write(p)
}

package operations_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/gatework/firemon/operations"
)

type requestReader func([]byte) (int, error)

func (r requestReader) Read(p []byte) (int, error) { return r(p) }

func TestJSONDecodersPropagateCancellation(t *testing.T) {
	for _, decode := range []struct {
		name string
		run  func(context.Context, io.Reader) error
	}{
		{"request", func(ctx context.Context, r io.Reader) error {
			_, err := operations.DecodeBatchRequest(ctx, r)
			return err
		}},
		{"topology", func(ctx context.Context, r io.Reader) error {
			_, err := operations.DecodeTopology(ctx, r)
			return err
		}},
	} {
		t.Run(decode.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reads := 0
			r := requestReader(func(p []byte) (int, error) {
				reads++
				if reads == 1 {
					cancel()
					return copy(p, "{"), nil
				}
				return 0, io.EOF
			})
			if err := decode.run(ctx, r); !errors.Is(err, context.Canceled) || reads != 1 {
				t.Fatalf("decoder lost cancellation: %v, %d reads", err, reads)
			}
			if err := decode.run(ctx, r); !errors.Is(err, context.Canceled) || reads != 1 {
				t.Fatalf("decoder read after cancellation: %v, %d reads", err, reads)
			}
		})
	}
}

func TestBatchJSONErrors(t *testing.T) {
	var typedNil *bytes.Buffer
	failure := errors.New("request reader failed")
	for _, tc := range []struct {
		name   string
		reader io.Reader
		want   error
		text   string
	}{
		{name: "nil", want: operations.ErrInvalid},
		{name: "typed nil", reader: typedNil, want: operations.ErrInvalid},
		{name: "reader error", reader: reconstructionIO{failure}, want: failure},
		{
			name: "byte limit", reader: strings.NewReader(strings.Repeat(" ", operations.MaxRequestBytes+1)),
			want: operations.ErrInvalid, text: operations.ErrInvalid.Error() + ": request exceeds byte limit",
		},
		{
			name: "trailing data", reader: strings.NewReader(`{} !`),
			want: operations.ErrInvalid, text: operations.ErrInvalid.Error() + ": trailing JSON",
		},
		{name: "unknown field", reader: strings.NewReader(`{"unknown":true}`), text: `json: unknown field "unknown"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := operations.DecodeBatchRequest(t.Context(), tc.reader)
			if err == nil || request.Version != 0 || request.Requests != nil {
				t.Fatal("partial request returned", request, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) || tc.text != "" && err.Error() != tc.text {
				t.Fatal("request error changed", err)
			}
		})
	}
	_, err := operations.DecodeBatchRequest(t.Context(), strings.NewReader(`{"version":"wrong"}`))
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) || errors.Is(err, operations.ErrInvalid) {
		t.Fatal("JSON type error changed", err)
	}
}

func TestBatchJSONZeroTime(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  string
	}{
		{value: operations.AccessDocument{}, want: `{}`},
		{value: operations.PolicyDocument{}, want: `{"from_zone":"","to_zone":""}`},
	} {
		raw, err := json.Marshal(tc.value)
		if err != nil || string(raw) != tc.want {
			t.Fatalf("zero time encoding changed: %s, %v", raw, err)
		}
	}
}

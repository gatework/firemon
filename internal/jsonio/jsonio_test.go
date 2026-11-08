package jsonio_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon/internal/jsonio"
)

func TestReadLimit(t *testing.T) {
	const limit = 3
	for _, input := range []string{"abc", "abcdef"} {
		r := strings.NewReader(input)
		raw, err := jsonio.Read(t.Context(), r, limit)
		if len(input) <= limit {
			if err != nil || string(raw) != input {
				t.Fatalf("exact limit: %q, %v", raw, err)
			}
			continue
		}
		if raw != nil || err != jsonio.ErrLimit || len(input)-r.Len() != limit+1 {
			t.Fatalf("overflow: %q, %v, %d unread bytes", raw, err, r.Len())
		}
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestReadFailure(t *testing.T) {
	failure := errors.New("reader failed")
	for _, tc := range []struct {
		name    string
		before  bool
		cancel  bool
		readErr error
		want    error
	}{
		{name: "reader error", readErr: failure, want: failure},
		{name: "already canceled", before: true, want: context.Canceled},
		{name: "canceled while reading", cancel: true, readErr: io.EOF, want: context.Canceled},
		{name: "reader error precedes cancellation", cancel: true, readErr: failure, want: failure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.before {
				cancel()
			}
			r := readerFunc(func(p []byte) (int, error) {
				if tc.before {
					t.Fatal("read after cancellation")
				}
				if tc.cancel {
					cancel()
				}
				return copy(p, "data"), tc.readErr
			})
			raw, err := jsonio.Read(ctx, r, 4)
			if raw != nil || err != tc.want {
				t.Fatalf("partial result or changed error: %q, %v", raw, err)
			}
		})
	}
}

func TestReadChecksCancellationBetweenReads(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reads := 0
	r := readerFunc(func(p []byte) (int, error) {
		reads++
		if reads == 1 {
			cancel()
			return copy(p, "x"), nil
		}
		return 0, io.EOF
	})
	raw, err := jsonio.Read(ctx, r, 10)
	if raw != nil || !errors.Is(err, context.Canceled) || reads != 1 {
		t.Fatalf("continued reading after cancellation: %q, %v, %d reads", raw, err, reads)
	}
}

func TestReadNoProgress(t *testing.T) {
	reads := 0
	r := readerFunc(func([]byte) (int, error) {
		reads++
		if reads > 100 {
			return 0, io.EOF
		}
		return 0, nil
	})
	raw, err := jsonio.Read(t.Context(), r, 10)
	if raw != nil || !errors.Is(err, io.ErrNoProgress) || reads != 100 {
		t.Fatalf("reader made no progress: %q, %v, %d reads", raw, err, reads)
	}
}

func TestReadProgressResetsEmptyReadLimit(t *testing.T) {
	reads := 0
	r := readerFunc(func(p []byte) (int, error) {
		reads++
		if reads > 200 {
			return 0, io.EOF
		}
		if reads%100 == 0 {
			return copy(p, "x"), nil
		}
		return 0, nil
	})
	raw, err := jsonio.Read(t.Context(), r, 10)
	if err != nil || string(raw) != "xx" {
		t.Fatalf("progress did not reset the empty read limit: %q, %v", raw, err)
	}
}

func TestDecodeStrict(t *testing.T) {
	var dst struct {
		Value int `json:"value"`
	}
	if err := jsonio.Decode([]byte("{\"value\":7}\n\t "), &dst); err != nil || dst.Value != 7 {
		t.Fatal(dst, err)
	}
	if err := jsonio.Decode([]byte(`{"unknown":7}`), &dst); err == nil {
		t.Fatal("unknown field accepted")
	}
	for _, suffix := range []string{` {}`, ` null`, ` !`, ` {`} {
		if err := jsonio.Decode([]byte(`{"value":7}`+suffix), &dst); err != jsonio.ErrTrailing {
			t.Fatalf("trailing %q: %v", suffix, err)
		}
	}
	var typeErr *json.UnmarshalTypeError
	if err := jsonio.Decode([]byte(`{"value":"wrong"}`), &dst); !errors.As(err, &typeErr) {
		t.Fatalf("lost JSON type error: %v", err)
	}
	if err := jsonio.Decode(nil, &dst); err != io.EOF {
		t.Fatalf("empty input: %v", err)
	}
}

func TestEncodeBytesAndLimit(t *testing.T) {
	value := struct {
		At   time.Time `json:"at"`
		Text string    `json:"text"`
	}{Text: "<>&"}
	const want = "{\"at\":\"0001-01-01T00:00:00Z\",\"text\":\"\\u003c\\u003e\\u0026\"}\n"
	raw, err := jsonio.Encode(t.Context(), value, len(want))
	if err != nil || string(raw) != want {
		t.Fatalf("encoding bytes changed: %q, %v", raw, err)
	}
	if raw, err := jsonio.Encode(t.Context(), value, len(want)-1); raw != nil || err != jsonio.ErrLimit {
		t.Fatalf("newline exceeded limit: %q, %v", raw, err)
	}
}

type marshalFunc func() ([]byte, error)

func (f marshalFunc) MarshalJSON() ([]byte, error) { return f() }

func TestEncodeFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	value := marshalFunc(func() ([]byte, error) {
		cancel()
		return []byte(`"value"`), nil
	})
	if raw, err := jsonio.Encode(ctx, value, 100); raw != nil || err != context.Canceled {
		t.Fatalf("canceled encoding: %q, %v", raw, err)
	}
	if raw, err := jsonio.Encode(ctx, nil, 100); raw != nil || err != context.Canceled {
		t.Fatalf("encoding after cancellation: %q, %v", raw, err)
	}
	failure := errors.New("marshal failed")
	value = marshalFunc(func() ([]byte, error) { return nil, failure })
	raw, err := jsonio.Encode(t.Context(), value, 100)
	var marshalErr *json.MarshalerError
	if raw != nil || !errors.Is(err, failure) || !errors.As(err, &marshalErr) {
		t.Fatalf("lost marshal error: %q, %v", raw, err)
	}
}

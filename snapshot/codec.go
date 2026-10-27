// Package snapshot persists trusted local, versioned gob firewall graphs.
package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	fm "github.com/gatework/firemon"
	"io"
)

const DefaultMaxBytes int64 = 128 << 20
const formatVersion uint16 = 1
const semanticVersion uint16 = 3

var magic = [8]byte{'F', 'I', 'R', 'E', 'M', 'O', 'N', 0}
var ErrFormat = errors.New("unsupported or corrupt snapshot")

type payload struct {
	SemanticDigest string
	Data           fm.Data
}

// Encode stores concrete tables and IDs. Runtime pointers and callbacks never enter the gob payload.
func Encode(w io.Writer, f *fm.Firewall) error {
	if f == nil {
		return ErrFormat
	}
	var body bytes.Buffer
	if err := gob.NewEncoder(&body).Encode(payload{SemanticDigest: f.SemanticDigest(), Data: f.Export()}); err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	if int64(body.Len()) > DefaultMaxBytes {
		return fmt.Errorf("%w: payload too large", ErrFormat)
	}
	header := make([]byte, 52)
	copy(header, magic[:])
	binary.BigEndian.PutUint16(header[8:10], formatVersion)
	binary.BigEndian.PutUint16(header[10:12], semanticVersion)
	binary.BigEndian.PutUint64(header[12:20], uint64(body.Len()))
	sum := sha256.Sum256(body.Bytes())
	copy(header[20:], sum[:])
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(body.Bytes())
	return err
}

// Decode bounds the envelope before gob decoding. gob files must come from trusted local storage.
func Decode(r io.Reader, maxBytes int64) (*fm.Firewall, error) {
	if maxBytes <= 0 {
		return nil, ErrFormat
	}
	header := make([]byte, 52)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrFormat, err)
	}
	if !bytes.Equal(header[:8], magic[:]) || binary.BigEndian.Uint16(header[8:10]) != formatVersion || binary.BigEndian.Uint16(header[10:12]) != semanticVersion {
		return nil, ErrFormat
	}
	n := binary.BigEndian.Uint64(header[12:20])
	if n > uint64(maxBytes) || n == 0 {
		return nil, ErrFormat
	}
	body := make([]byte, int(n))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrFormat, err)
	}
	var extra [1]byte
	if n, err := r.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrFormat)
	}
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], header[20:]) {
		return nil, fmt.Errorf("%w: checksum", ErrFormat)
	}
	var p payload
	decoder := gob.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: gob: %v", ErrFormat, err)
	}
	var trailing payload
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing gob value", ErrFormat)
	}
	fw, err := fm.Seal(p.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: graph: %v", ErrFormat, err)
	}
	if fw.SemanticDigest() != p.SemanticDigest {
		return nil, fmt.Errorf("%w: semantic digest", ErrFormat)
	}
	return fw, nil
}

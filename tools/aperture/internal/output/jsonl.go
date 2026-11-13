package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"aperture/internal/model"
)

// JSONLWriter writes Findings as JSON Lines (one JSON object per line).
// It is safe for concurrent use — all writes are serialised by a mutex.
// The format is streaming-friendly: the file can be read line-by-line
// before the scan completes using `tail -f findings.jsonl | jq .`
type JSONLWriter struct {
	mu     sync.Mutex
	w      *bufio.Writer
	file   *os.File
	count  int
	closed bool
}

// NewJSONLWriter opens the given file path for append-write JSONL output.
// If path is "-", writes to stdout.
func NewJSONLWriter(path string) (*JSONLWriter, error) {
	if path == "-" {
		return &JSONLWriter{w: bufio.NewWriter(os.Stdout)}, nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening JSONL output %q: %w", path, err)
	}

	return &JSONLWriter{
		w:    bufio.NewWriterSize(f, 64*1024),
		file: f,
	}, nil
}

// Write serialises a Finding as a single JSON line and flushes it.
// Returns an error only on actual I/O failure.
func (j *JSONLWriter) Write(f *model.Finding) error {
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshalling finding %q: %w", f.ID, err)
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return fmt.Errorf("writer is closed")
	}

	if _, err := j.w.Write(data); err != nil {
		return err
	}
	if err := j.w.WriteByte('\n'); err != nil {
		return err
	}
	// Flush after each finding so partial outputs are readable immediately.
	if err := j.w.Flush(); err != nil {
		return err
	}
	j.count++
	return nil
}

// Count returns the number of findings written so far.
func (j *JSONLWriter) Count() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.count
}

// Close flushes any buffered data and closes the underlying file.
func (j *JSONLWriter) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return nil
	}
	j.closed = true

	if err := j.w.Flush(); err != nil {
		return err
	}
	if j.file != nil {
		return j.file.Close()
	}
	return nil
}

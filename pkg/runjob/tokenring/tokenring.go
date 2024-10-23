package tokenring

import (
	"errors"
	"io"
	"sync"
)

// TokenRingBuffer is a thread-safe buffer with unlimited capacity.
type TokenRingBuffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
}

// NewTokenRingBuffer creates a new TokenRingBuffer.
func NewTokenRingBuffer() *TokenRingBuffer {
	trb := &TokenRingBuffer{}
	trb.cond = sync.NewCond(&trb.mu)
	return trb
}

// Write appends data to the buffer, implementing io.Writer.
func (b *TokenRingBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return 0, io.ErrClosedPipe
	}

	b.buf = append(b.buf, p...)
	b.cond.Broadcast() // Notify readers that new data is available
	return len(p), nil
}

// Close closes the buffer, signaling readers that no more data will come.
func (b *TokenRingBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return io.ErrClosedPipe
	}

	b.closed = true
	b.cond.Broadcast() // Wake up all waiting readers
	return nil
}

// NewReader returns a new reader that reads from the buffer.
func (b *TokenRingBuffer) NewReader() io.ReadCloser {
	return &bufferReader{
		buffer: b,
		pos:    0,
	}
}

// ReadFrom reads data from an io.Reader and writes it into the buffer.
func (b *TokenRingBuffer) ReadFrom(reader io.Reader) error {
	if reader == nil {
		return errors.New("invalid argument: reader is nil")
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				_, writeErr := b.Write(buf[:n])
				if writeErr != nil {
					// Handle write error (e.g., buffer closed)
					break
				}
			}
			if err != nil {
				if err == io.EOF {
					// Close the buffer if the source reader reaches EOF
					b.Close()
				}
				// Break on any read error
				break
			}
		}
	}()
	return nil
}

// bufferReader reads from TokenRingBuffer and implements io.ReadCloser.
type bufferReader struct {
	buffer *TokenRingBuffer
	mu     sync.Mutex // Protects pos and closed
	pos    int        // Read position
	closed bool
}

// Ensure bufferReader implements io.ReadCloser.
var _ io.ReadCloser = (*bufferReader)(nil)

// Read reads data from the buffer, implementing io.Reader.
func (r *bufferReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return 0, io.ErrClosedPipe
	}

	b := r.buffer

	b.mu.Lock()
	defer b.mu.Unlock()

	for {
		if r.pos < len(b.buf) {
			n := copy(p, b.buf[r.pos:])
			r.pos += n
			return n, nil
		}

		if b.closed {
			return 0, io.EOF
		}

		// Wait for new data to be written
		b.cond.Wait()
	}
}

// Close closes the reader, implementing io.Closer.
func (r *bufferReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return io.ErrClosedPipe
	}

	r.closed = true
	return nil
}

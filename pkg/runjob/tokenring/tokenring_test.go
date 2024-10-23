package tokenring

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAndRead(t *testing.T) {
	buffer := NewTokenRingBuffer()

	data := []byte("Hello, TokenRingBuffer!")
	n, err := buffer.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)

	reader := buffer.NewReader()
	defer reader.Close()

	buf := make([]byte, len(data))
	n, err = io.ReadFull(reader, buf)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf)
}

func TestConcurrentReaders(t *testing.T) {
	t.Parallel()

	buffer := NewTokenRingBuffer()

	data := []byte("Concurrent readers test data.")
	n, err := buffer.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)

	var wg sync.WaitGroup
	numReaders := 10
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reader := buffer.NewReader()
			defer reader.Close()

			buf := make([]byte, len(data))
			n, err := io.ReadFull(reader, buf)
			require.NoError(t, err)
			assert.Equal(t, len(data), n)
			assert.Equal(t, data, buf)
		}()
	}

	wg.Wait()
}

func TestReadersAtDifferentSpeeds(t *testing.T) {
	t.Parallel()

	buffer := NewTokenRingBuffer()

	dataChunks := []string{"Chunk1 ", "Chunk2 ", "Chunk3 ", "Chunk4 ", "Chunk5 "}
	totalData := ""
	for _, chunk := range dataChunks {
		totalData += chunk
	}

	var wg sync.WaitGroup
	numReaders := 3

	// Start readers
	for i := 1; i <= numReaders; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			reader := buffer.NewReader()
			defer reader.Close()

			buf := make([]byte, 7)
			totalRead := ""
			for {
				n, err := reader.Read(buf)
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
				totalRead += string(buf[:n])
				// Simulate different speeds
				time.Sleep(time.Duration(id*10) * time.Millisecond)
			}
			assert.Equal(t, totalData, totalRead)
		}(i)
	}

	// Start writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, chunk := range dataChunks {
			_, err := buffer.Write([]byte(chunk))
			require.NoError(t, err)
			time.Sleep(20 * time.Millisecond)
		}
		buffer.Close()
	}()

	wg.Wait()
}

func TestReaderBlocksUntilDataAvailable(t *testing.T) {
	buffer := NewTokenRingBuffer()

	reader := buffer.NewReader()
	defer reader.Close()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 5)
		n, err := reader.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("Hello"), buf)
		close(done)
	}()

	// Wait to ensure the reader is blocked
	time.Sleep(100 * time.Millisecond)

	n, err := buffer.Write([]byte("Hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)

	select {
	case <-done:
		// Test passed
	case <-time.After(1 * time.Second):
		t.Fatal("Test timed out waiting for reader to receive data")
	}
}

func TestReaderReceivesEOFWhenBufferClosed(t *testing.T) {
	buffer := NewTokenRingBuffer()

	reader := buffer.NewReader()
	defer reader.Close()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		n, err := reader.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
		close(done)
	}()

	// Wait to ensure the reader is blocked
	time.Sleep(100 * time.Millisecond)

	err := buffer.Close()
	require.NoError(t, err)

	select {
	case <-done:
		// Test passed
	case <-time.After(1 * time.Second):
		t.Fatal("Test timed out waiting for reader to receive EOF")
	}
}

func TestReaderClose(t *testing.T) {
	buffer := NewTokenRingBuffer()

	reader := buffer.NewReader()
	err := reader.Close()
	require.NoError(t, err)

	// Subsequent reads should return io.ErrClosedPipe
	buf := make([]byte, 10)
	n, err := reader.Read(buf)
	assert.Equal(t, 0, n)
	assert.Equal(t, io.ErrClosedPipe, err)

	// Closing again should return io.ErrClosedPipe
	err = reader.Close()
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestWriteAfterBufferClosed(t *testing.T) {
	buffer := NewTokenRingBuffer()

	err := buffer.Close()
	require.NoError(t, err)

	n, err := buffer.Write([]byte("data"))
	assert.Equal(t, 0, n)
	assert.Equal(t, io.ErrClosedPipe, err)
}

func TestReadFromEmptyClosedBuffer(t *testing.T) {
	buffer := NewTokenRingBuffer()

	err := buffer.Close()
	require.NoError(t, err)

	reader := buffer.NewReader()
	defer reader.Close()

	buf := make([]byte, 10)
	n, err := reader.Read(buf)
	assert.Equal(t, 0, n)
	assert.Equal(t, io.EOF, err)
}

func TestReadersStartFromBeginning(t *testing.T) {
	buffer := NewTokenRingBuffer()

	data := []byte("Data before reader starts.")
	_, err := buffer.Write(data)
	require.NoError(t, err)

	reader := buffer.NewReader()
	defer reader.Close()

	buf := make([]byte, len(data))
	n, err := io.ReadFull(reader, buf)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf)
}

func TestReaderBlocksWhenNoDataAndBufferNotClosed(t *testing.T) {
	buffer := NewTokenRingBuffer()

	reader := buffer.NewReader()
	defer reader.Close()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		n, err := reader.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
		close(done)
	}()

	// Wait to ensure the reader is blocked
	time.Sleep(100 * time.Millisecond)

	// Close the buffer without writing any data
	err := buffer.Close()
	require.NoError(t, err)

	select {
	case <-done:
		// Test passed
	case <-time.After(1 * time.Second):
		t.Fatal("Test timed out waiting for reader to receive EOF")
	}
}

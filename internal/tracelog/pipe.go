package tracelog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// pollTimeout bounds how long a read waits on the pipe before re-checking the
// context, so cancellation is prompt.
const pollTimeout = 200 * time.Millisecond

// pipeReader reads a tracefs trace_pipe. The file is opened non-blocking and
// each read is gated by poll(2): a blocking read on trace_pipe returns only when
// the kernel has a next line to give, which would leave the reader goroutine
// parked - still holding the pipe open, still draining it - long after the last
// client left.
type pipeReader struct {
	ctx  context.Context
	fd   int
	path string
}

func openPipe(ctx context.Context, path string) (*pipeReader, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return &pipeReader{ctx: ctx, fd: fd, path: path}, nil
}

// Read blocks until the pipe has data, the context is done (returning its
// error), or the pipe fails. It never returns (0, nil).
func (p *pipeReader) Read(b []byte) (int, error) {
	for {
		if err := p.ctx.Err(); err != nil {
			return 0, err
		}

		fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, int(pollTimeout.Milliseconds()))
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, fmt.Errorf("poll %s: %w", p.path, err)
		}
		if n == 0 {
			continue // timed out with no data: re-check the context
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			// POLLERR/POLLHUP/POLLNVAL with no data to read: the pipe is gone.
			return 0, fmt.Errorf("poll %s: revents 0x%x", p.path, fds[0].Revents)
		}

		nr, err := unix.Read(p.fd, b)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, fmt.Errorf("read %s: %w", p.path, err)
		}
		if nr == 0 {
			// trace_pipe has no end of file; a short poll can still race with
			// another reader taking the line. Wait for the next one.
			continue
		}
		return nr, nil
	}
}

func (p *pipeReader) Close() error { return unix.Close(p.fd) }

// openTracePipe is Hub's default opener: resolve tracefs, then open the pipe.
func openTracePipe(ctx context.Context) (io.ReadCloser, string, error) {
	path, err := FindTracePipe()
	if err != nil {
		return nil, "", err
	}
	r, err := openPipe(ctx, path)
	if err != nil {
		return nil, "", err
	}
	return r, path, nil
}

package meek

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

func newClientSession(ctx context.Context, tripper Tripper, config *config, workers *sync.WaitGroup) (*assemblerClientSession, error) {
	sessionID := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, sessionID)
	if err != nil {
		return nil, err
	}

	sessionContext, finish := context.WithCancel(ctx)

	session := &assemblerClientSession{
		sessionID:        sessionID,
		currentWriteWait: int(config.InitialPollingIntervalMs),
		ctx:              sessionContext,
		tripper:          tripper,
		config:           config,
		finish:           finish,
		readBuffer:       bytes.NewBuffer(nil),
		writerChan:       make(chan []byte),
		readerChan:       make(chan []byte, 16),
		done:             make(chan struct{}),
	}

	if workers != nil {
		workers.Add(1)
	}
	go func() {
		defer close(session.done)
		if workers != nil {
			defer workers.Done()
		}
		session.keepRunning()
	}()

	return session, nil
}

type assemblerClientSession struct {
	sessionID        []byte
	currentWriteWait int

	tripper    Tripper
	config     *config
	readBuffer *bytes.Buffer
	writerChan chan []byte
	readerChan chan []byte
	ctx        context.Context
	finish     func()
	done       chan struct{}
}

var _ net.Conn = (*assemblerClientSession)(nil)

func (s *assemblerClientSession) SetDeadline(t time.Time) error {
	return nil
}

func (s *assemblerClientSession) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *assemblerClientSession) SetWriteDeadline(t time.Time) error {
	return nil
}

func (s *assemblerClientSession) keepRunning() {
	for s.ctx.Err() == nil {
		s.runOnce()
	}
}

func (s *assemblerClientSession) runOnce() {
	sendBuffer := bytes.NewBuffer(nil)
	if s.currentWriteWait != 0 {
		waitTimer := time.NewTimer(time.Millisecond * time.Duration(s.currentWriteWait))
		waitForFirstWrite := true
	copyFromWriterLoop:
		for {
			select {
			case <-s.ctx.Done():
				return
			case data := <-s.writerChan:
				sendBuffer.Write(data)
				if sendBuffer.Len() >= int(s.config.MaxWriteSize) {
					break copyFromWriterLoop
				}
				if waitForFirstWrite {
					waitForFirstWrite = false
					waitTimer.Reset(time.Millisecond * time.Duration(s.config.WaitSubsequentWriteMs))
				}
			case <-waitTimer.C:
				break copyFromWriterLoop
			}
		}
		waitTimer.Stop()
	}

	firstRound := true
	pollConnection := true
	for sendBuffer.Len() != 0 || firstRound {
		firstRound = false
		sendAmount := sendBuffer.Len()
		if sendAmount > int(s.config.MaxWriteSize) {
			sendAmount = int(s.config.MaxWriteSize)
		}
		data := sendBuffer.Next(sendAmount)
		if len(data) != 0 {
			pollConnection = false
		}
		for {
			ctx, cancel := netproxy.NewDialTimeoutContextFrom(s.ctx)
			resp, err := s.tripper.RoundTrip(ctx, Request{Data: data, ConnectionTag: s.sessionID})
			ctxErr := ctx.Err()
			cancel()
			if err != nil {
				if ctxErr != nil {
					return
				}
				retry := time.NewTimer(time.Millisecond * time.Duration(s.config.FailedRetryIntervalMs))
				select {
				case <-s.ctx.Done():
					retry.Stop()
					return
				case <-retry.C:
				}
				continue
			}
			if len(resp.Data) != 0 {
				pollConnection = false
				select {
				case s.readerChan <- resp.Data:
				case <-s.ctx.Done():
					return
				}
			}
			break
		}
	}
	if pollConnection {
		s.currentWriteWait = int(s.config.BackoffFactor * float32(s.currentWriteWait))
		if s.currentWriteWait > int(s.config.MaxPollingIntervalMs) {
			s.currentWriteWait = int(s.config.MaxPollingIntervalMs)
		}
		if s.currentWriteWait < int(s.config.MinPollingIntervalMs) {
			s.currentWriteWait = int(s.config.MinPollingIntervalMs)
		}
	} else {
		s.currentWriteWait = 0
	}
}

func (s *assemblerClientSession) Read(p []byte) (n int, err error) {
	if s.readBuffer.Len() == 0 {
		select {
		case <-s.ctx.Done():
			return 0, s.ctx.Err()
		case data := <-s.readerChan:
			s.readBuffer.Write(data)
		}
	}
	n, err = s.readBuffer.Read(p)
	if err == io.EOF {
		s.readBuffer.Reset()
		return 0, nil
	}
	return
}

func (s *assemblerClientSession) Write(p []byte) (n int, err error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	case s.writerChan <- buf:
		return len(p), nil
	}
}

func (s *assemblerClientSession) Close() error {
	s.finish()
	<-s.done
	return nil
}

func (s *assemblerClientSession) LocalAddr() net.Addr  { return nil }
func (s *assemblerClientSession) RemoteAddr() net.Addr { return nil }

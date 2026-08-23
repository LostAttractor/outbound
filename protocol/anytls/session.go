package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*stream
	streamLock sync.RWMutex

	padding     atomic.Value
	sendPadding bool
	pktCounter  atomic.Uint32
	peerVersion byte

	sid       atomic.Uint32
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	onIdle    func(*session)
}

func newSession(conn net.Conn, onIdle func(*session)) *session {
	s := &session{
		conn:        conn,
		streams:     map[uint32]*stream{},
		onIdle:      onIdle,
		sendPadding: true,
	}
	s.padding.Store(DefaultPaddingFactory.Load())
	return s
}

func (s *session) newStream(addr string) (*stream, error) {
	tgtAddr, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	sid := s.sid.Add(1)
	stream := newStream(s, sid)
	s.streamLock.Lock()
	if s.closed.Load() {
		s.streamLock.Unlock()
		stream.sessionClose()
		return nil, net.ErrClosed
	}
	s.streams[sid] = stream
	s.streamLock.Unlock()
	cleanup := func() {
		s.streamLock.Lock()
		if s.streams[sid] == stream {
			delete(s.streams, sid)
		}
		s.streamLock.Unlock()
		stream.sessionClose()
	}

	frame := newFrame(cmdSettings, sid)
	frame.data = settingsBytes(s.GetPadding())
	if _, err := writeFrame(s, frame); err != nil {
		cleanup()
		return nil, err
	}

	frame = newFrame(cmdSYN, sid)
	if _, err := writeFrame(s, frame); err != nil {
		cleanup()
		return nil, err
	}

	frame = newFrame(cmdPSH, sid)
	frame.data = tgtAddr
	if _, err := writeFrame(s, frame); err != nil {
		cleanup()
		return nil, err
	}
	if s.closed.Load() || stream.closed.Load() {
		cleanup()
		return nil, net.ErrClosed
	}

	return stream, nil
}

func (s *session) newPacketStream(addr, packetAddr string) (*packetStream, error) {
	stream, err := s.newStream(addr)
	if err != nil {
		return nil, err
	}
	return &packetStream{
		stream: stream,
		addr:   packetAddr,
	}, nil
}

func (s *session) removeStream(sid uint32) {
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	if s.onIdle != nil {
		s.onIdle(s)
	}
}

func (s *session) run() (err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[Panic]", slog.String("stack", string(debug.Stack())))
			err = fmt.Errorf("anytls session panic: %v", r)
		}
	}()
	defer s.Close()

	var header rawHeader
	for {
		if s.closed.Load() {
			return net.ErrClosed
		}
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			return err
		}
		sid := header.StreamID()
		length := int(header.Length())
		switch header.Cmd() {
		case cmdWaste:
			if _, err := io.CopyN(io.Discard, s.conn, int64(length)); err != nil {
				return err
			}
		case cmdPSH:
			buf := pool.GetBuffer(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.PutBuffer(buf)
				return err
			}
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				if _, err := stream.pw.Write(buf); err != nil {
					pool.PutBuffer(buf)
					return err
				}
			}
			pool.PutBuffer(buf)
		case cmdAlert:
			buf := pool.GetBuffer(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.PutBuffer(buf)
				return err
			}
			slog.Error("[Alert]", slog.String("msg", string(buf)))
			pool.PutBuffer(buf)
		case cmdFIN:
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				stream.remoteClose()
			}
		case cmdUpdatePaddingScheme:
			if length > 0 {
				buf := pool.GetBuffer(length)
				if _, err := io.ReadFull(s.conn, buf); err != nil {
					pool.PutBuffer(buf)
					return err
				}
				updatePaddingScheme(buf)
				pool.PutBuffer(buf)
			}
		case cmdSYNACK:
			if length > 0 {
				buf := pool.GetBuffer(length)
				if _, err := io.ReadFull(s.conn, buf); err != nil {
					pool.PutBuffer(buf)
					return err
				}
				s.streamLock.RLock()
				stream, ok := s.streams[sid]
				s.streamLock.RUnlock()
				if ok {
					stream.Close()
				}
				pool.PutBuffer(buf)
			}
		case cmdServerSettings:
			if length > 0 {
				buffer := pool.GetBuffer(length)
				if _, err := io.ReadFull(s.conn, buffer); err != nil {
					pool.PutBuffer(buffer)
					return err
				}
				// check server's version
				m := stringMapFromBytes(buffer)
				if v, err := strconv.Atoi(m["v"]); err == nil {
					s.peerVersion = byte(v)
				}
				pool.PutBuffer(buffer)
			}

		case cmdHeartRequest:
			frame := newFrame(cmdHeartResponse, sid)
			if _, err := writeFrame(s, frame); err != nil {
				return err
			}
		case cmdHeartResponse:
		default:
			return fmt.Errorf("invalid cmd: %d", header.Cmd())
		}
	}
}

func (s *session) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.streamLock.Lock()
		streams := make([]*stream, 0, len(s.streams))
		for _, stream := range s.streams {
			streams = append(streams, stream)
		}
		s.streams = make(map[uint32]*stream)
		s.streamLock.Unlock()
		for _, stream := range streams {
			stream.sessionClose()
		}
		s.closeErr = s.conn.Close()
	})
	return s.closeErr
}

func (s *session) SetPadding(padding *paddingFactory) {
	s.padding.Store(padding)
}

func (s *session) GetPadding() *paddingFactory {
	return s.padding.Load().(*paddingFactory)
}

func (s *session) writeConn(b []byte) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	// calulate & send padding
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.GetPadding()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == CheckMark {
					if remainPayloadLen == 0 {
						break
					} else {
						continue
					}
				}
				// logrus.Debugln(pkt, "write", l, "len", remainPayloadLen, "remain", remainPayloadLen-l)
				if remainPayloadLen > l { // this packet is all payload
					_, err = s.conn.Write(b[:l])
					if err != nil {
						return 0, err
					}
					n += l
					b = b[l:]
				} else if remainPayloadLen > 0 { // this packet contains padding and the last part of payload
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						padding := make([]byte, headerOverHeadSize+paddingLen)
						padding[0] = cmdWaste
						binary.BigEndian.PutUint32(padding[1:5], 0)
						binary.BigEndian.PutUint16(padding[5:7], uint16(paddingLen))
						b = slices.Concat(b, padding)
					}
					_, err = s.conn.Write(b)
					if err != nil {
						return 0, err
					}
					n += remainPayloadLen
					b = nil
				} else { // this packet is all padding
					padding := make([]byte, headerOverHeadSize+l)
					padding[0] = cmdWaste
					binary.BigEndian.PutUint32(padding[1:5], 0)
					binary.BigEndian.PutUint16(padding[5:7], uint16(l))
					_, err = s.conn.Write(padding)
					if err != nil {
						return 0, err
					}
					b = nil
				}
			}
			// maybe still remain payload to write
			if len(b) == 0 {
				return
			} else {
				n2, err := s.conn.Write(b)
				return n + n2, err
			}
		} else {
			s.sendPadding = false
		}
	}

	return s.conn.Write(b)
}

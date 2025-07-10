// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

type Session struct {
	started uint32
	outputs []string
	tstamps []uint32
	lastidx int
}

type Sessions struct {
	sessions map[uint64]*Session
}

func NewSessions() *Sessions {
	return &Sessions{
		sessions: make(map[uint64]*Session),
	}
}

func (s *Sessions) Add(sessID uint64, started uint32, maxDepth uint, graph bool) *Session {
	sess := &Session{
		started: started,
	}
	if graph {
		sess.tstamps = make([]uint32, 0, maxDepth+1)
		sess.tstamps = append(sess.tstamps, started)
	}
	s.sessions[sessID] = sess
	return sess
}

func (s *Sessions) Get(sessID uint64) (*Session, bool) {
	sess, ok := s.sessions[sessID]
	return sess, ok
}

func (s *Sessions) GetAndDel(sessID uint64) (*Session, bool) {
	sess, ok := s.sessions[sessID]
	if ok {
		delete(s.sessions, sessID)
	}
	return sess, ok
}

func (s *Session) lastTstamp() uint32 {
	return s.tstamps[s.lastidx]
}

func (s *Session) pushTstamp(ts uint32) {
	s.tstamps = append(s.tstamps, ts)
	s.lastidx++
}

func (s *Session) popTstamp() {
	s.tstamps = s.tstamps[:s.lastidx]
	s.lastidx--
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Wire format (every packet, data and handshake alike):
//
//	[ idx(4) | ctr(8) ]  masked header, 12 bytes
//	[ AEAD ciphertext ]  AES-256-GCM, nonce = unmasked header, AD = unmasked header
//	[ tag(16) ]
//
// Overhead is 28 bytes per data packet (WireGuard: 32). The header is hidden
// QUIC-style: mask = AES(obfsKey, first 16 bytes of ciphertext), so on the wire
// nothing is static or counting up. idx 0 marks a handshake packet; in that case
// ctr is 8 random bytes.
const (
	hdrLen   = 12
	tagLen   = 16
	overhead = hdrLen + tagLen
	maxIP    = 65535

	initBody = 32 + 8 + 4 // client ephemeral | timestamp | client idx
	respBody = 32 + 4 + 4 // server ephemeral | server idx | client idx
	maxPad   = 64

	maxCounter = 1 << 60
)

// Timers. Variables so tests can shorten them.
var (
	rekeyAfter     = 120 * time.Second // client starts a new handshake
	rejectAfter    = 180 * time.Second // keys are never used after this
	handshakeRetry = 3 * time.Second
	deadAfter      = 5 * time.Second // sent but heard nothing back for this long
)

var errAuth = errors.New("authentication failed")

func newBlock(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }

func newAEAD(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// mask XORs the header with AES(obfs, ciphertext sample). It is its own
// inverse because the sample is never masked. pkt must be >= overhead bytes.
func mask(obfs cipher.Block, pkt []byte) {
	var m [16]byte
	obfs.Encrypt(m[:], pkt[hdrLen:hdrLen+16])
	for i := 0; i < hdrLen; i++ {
		pkt[i] ^= m[i]
	}
}

// pskKeys are the static per-client keys that protect the two handshake
// messages. Possession of the PSK is what authenticates both sides.
type pskKeys struct {
	psk  []byte
	init cipher.AEAD
	resp cipher.AEAD
}

func newPSKKeys(psk []byte) (*pskKeys, error) {
	k := &pskKeys{psk: psk}
	for _, x := range []struct {
		dst  *cipher.AEAD
		info string
	}{{&k.init, "microtun v2 init"}, {&k.resp, "microtun v2 resp"}} {
		key, err := hkdf.Key(sha256.New, psk, nil, x.info, 32)
		if err != nil {
			return nil, err
		}
		if *x.dst, err = newAEAD(key); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func randPad(limit int) int {
	if limit <= 0 {
		return 0
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint16(b[:])) % (limit + 1)
}

// sealHandshake builds a masked handshake packet (idx 0, random nonce) from body
// plus pad random bytes.
func sealHandshake(obfs cipher.Block, aead cipher.AEAD, body, extraAD []byte, pad int) []byte {
	var hdr [hdrLen]byte
	_, _ = rand.Read(hdr[4:])
	pt := make([]byte, len(body)+pad)
	copy(pt, body)
	_, _ = rand.Read(pt[len(body):])
	pkt := make([]byte, hdrLen, hdrLen+len(pt)+tagLen)
	copy(pkt, hdr[:])
	pkt = aead.Seal(pkt, hdr[:], pt, append(hdr[:], extraAD...))
	mask(obfs, pkt)
	return pkt
}

// openHandshake opens an already unmasked handshake packet.
func openHandshake(aead cipher.AEAD, pkt, extraAD []byte, min int) ([]byte, error) {
	hdr := pkt[:hdrLen]
	pt, err := aead.Open(nil, hdr, pkt[hdrLen:], append(append([]byte(nil), hdr...), extraAD...))
	if err != nil || len(pt) < min {
		return nil, errAuth
	}
	return pt, nil
}

type initMsg struct {
	eph []byte
	ts  uint64
	idx uint32
}

func buildInit(obfs cipher.Block, k *pskKeys, m initMsg) []byte {
	body := make([]byte, initBody)
	copy(body, m.eph)
	binary.BigEndian.PutUint64(body[32:], m.ts)
	binary.BigEndian.PutUint32(body[40:], m.idx)
	return sealHandshake(obfs, k.init, body, nil, randPad(maxPad))
}

func parseInit(k *pskKeys, pkt []byte) (initMsg, bool) {
	pt, err := openHandshake(k.init, pkt, nil, initBody)
	if err != nil {
		return initMsg{}, false
	}
	return initMsg{
		eph: pt[:32],
		ts:  binary.BigEndian.Uint64(pt[32:]),
		idx: binary.BigEndian.Uint32(pt[40:]),
	}, true
}

type respMsg struct {
	eph       []byte
	serverIdx uint32
	clientIdx uint32
}

// buildResp never makes a response larger than the init it answers, so the
// server cannot be used to amplify traffic.
func buildResp(obfs cipher.Block, k *pskKeys, m respMsg, clientEph []byte, initLen int) []byte {
	body := make([]byte, respBody)
	copy(body, m.eph)
	binary.BigEndian.PutUint32(body[32:], m.serverIdx)
	binary.BigEndian.PutUint32(body[36:], m.clientIdx)
	room := initLen - (hdrLen + respBody + tagLen)
	return sealHandshake(obfs, k.resp, body, clientEph, randPad(min(room, maxPad)))
}

func parseResp(k *pskKeys, pkt, clientEph []byte) (respMsg, bool) {
	pt, err := openHandshake(k.resp, pkt, clientEph, respBody)
	if err != nil {
		return respMsg{}, false
	}
	return respMsg{
		eph:       pt[:32],
		serverIdx: binary.BigEndian.Uint32(pt[32:]),
		clientIdx: binary.BigEndian.Uint32(pt[36:]),
	}, true
}

// deriveKeys mixes the ephemeral X25519 secret with the PSK and binds both
// ephemerals and indexes, giving fresh keys (and forward secrecy) per session.
func deriveKeys(shared, psk, ephC, ephS []byte, idxC, idxS uint32) (c2s, s2c []byte, err error) {
	th := sha256.New()
	th.Write(ephC)
	th.Write(ephS)
	_ = binary.Write(th, binary.BigEndian, [2]uint32{idxC, idxS})
	sum := th.Sum(nil)
	if c2s, err = hkdf.Key(sha256.New, shared, psk, "microtun v2 c2s"+string(sum), 32); err != nil {
		return
	}
	s2c, err = hkdf.Key(sha256.New, shared, psk, "microtun v2 s2c"+string(sum), 32)
	return
}

func newEphemeral() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

func dh(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub) // rejects low-order points (all-zero result)
}

func randIdx() uint32 {
	for {
		var b [4]byte
		_, _ = rand.Read(b[:])
		if v := binary.BigEndian.Uint32(b[:]); v != 0 {
			return v
		}
	}
}

// replayWindow accepts each counter at most once and tolerates reordering of
// up to windowBits packets (duplicated burst copies land here and are dropped).
const windowBits = 1024

type replayWindow struct {
	mu   sync.Mutex
	seen bool
	max  uint64
	bits [windowBits / 64]uint64
}

func (r *replayWindow) accept(ctr uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.seen {
		r.seen, r.max = true, ctr
		r.set(ctr)
		return true
	}
	if ctr > r.max {
		if ctr-r.max >= windowBits {
			r.bits = [windowBits / 64]uint64{}
		} else {
			for c := r.max + 1; c < ctr; c++ {
				r.clear(c)
			}
		}
		r.max = ctr
		r.set(ctr)
		return true
	}
	if r.max-ctr >= windowBits || r.has(ctr) {
		return false
	}
	r.set(ctr)
	return true
}

func (r *replayWindow) set(c uint64)      { r.bits[(c/64)%(windowBits/64)] |= 1 << (c % 64) }
func (r *replayWindow) clear(c uint64)    { r.bits[(c/64)%(windowBits/64)] &^= 1 << (c % 64) }
func (r *replayWindow) has(c uint64) bool { return r.bits[(c/64)%(windowBits/64)]&(1<<(c%64)) != 0 }

// session is one set of transport keys. localIdx is what the other side puts
// in the header when sending to us; remoteIdx is what we put there.
type session struct {
	localIdx, remoteIdx uint32
	send, recv          cipher.AEAD
	ctr                 atomic.Uint64
	rw                  replayWindow
	born                time.Time
	peer                *peer // server side only
}

func newSession(localIdx, remoteIdx uint32, sendKey, recvKey []byte) (*session, error) {
	s := &session{localIdx: localIdx, remoteIdx: remoteIdx, born: time.Now()}
	var err error
	if s.send, err = newAEAD(sendKey); err != nil {
		return nil, err
	}
	if s.recv, err = newAEAD(recvKey); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *session) expired(now time.Time) bool { return now.Sub(s.born) >= rejectAfter }

// seal encrypts buf[hdrLen:hdrLen+n] in place. buf needs tagLen spare bytes
// after the payload. It returns nil once the session must not be used.
func (s *session) seal(obfs cipher.Block, buf []byte, n int) []byte {
	c := s.ctr.Add(1) - 1
	if c >= maxCounter || s.expired(time.Now()) {
		return nil
	}
	binary.BigEndian.PutUint32(buf[0:4], s.remoteIdx)
	binary.BigEndian.PutUint64(buf[4:12], c)
	ct := s.send.Seal(buf[hdrLen:hdrLen], buf[:hdrLen], buf[hdrLen:hdrLen+n], buf[:hdrLen])
	pkt := buf[:hdrLen+len(ct)]
	mask(obfs, pkt)
	return pkt
}

// open decrypts an unmasked data packet in place and enforces the replay window.
func (s *session) open(pkt []byte) ([]byte, bool) {
	if s.expired(time.Now()) {
		return nil, false
	}
	ctr := binary.BigEndian.Uint64(pkt[4:12])
	pt, err := s.recv.Open(pkt[hdrLen:hdrLen], pkt[:hdrLen], pkt[hdrLen:], pkt[:hdrLen])
	if err != nil || !s.rw.accept(ctr) {
		return nil, false
	}
	return pt, true
}

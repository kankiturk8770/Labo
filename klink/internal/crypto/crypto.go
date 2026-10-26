package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

func GenerateKeyPair() (*KeyPair, error) {
	var priv, pub [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	curve25519.ScalarBaseMult(&pub, &priv)
	return &KeyPair{Private: priv, Public: pub}, nil
}

func ComputeSharedSecret(priv, peerPub [32]byte) ([32]byte, error) {
	var shared [32]byte
	res, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return shared, err
	}
	copy(shared[:], res)
	return blake2s.Sum256(shared[:]), nil
}

type CipherState struct {
	mu        sync.RWMutex
	aead      cipher.AEAD
	rawKey    [32]byte
	createdAt time.Time
	txCount   uint64
}

func NewCipherState(sharedKey [32]byte) (*CipherState, error) {
	derivedKey := blake2s.Sum256(append([]byte("KLINK-V2-KEY"), sharedKey[:]...))
	aead, err := chacha20poly1305.New(derivedKey[:])
	if err != nil {
		return nil, err
	}
	return &CipherState{
		aead:      aead,
		rawKey:    derivedKey,
		createdAt: time.Now(),
	}, nil
}

func (cs *CipherState) CheckAndRekey() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if time.Since(cs.createdAt) < 10*time.Minute && cs.txCount < 1000000 {
		return nil
	}
	nextKey := blake2s.Sum256(append([]byte("KLINK-REKEY"), cs.rawKey[:]...))
	aead, err := chacha20poly1305.New(nextKey[:])
	if err != nil {
		return err
	}
	cs.aead = aead
	cs.rawKey = nextKey
	cs.createdAt = time.Now()
	cs.txCount = 0
	return nil
}

func (cs *CipherState) Encrypt(seq uint64, plaintext, ad []byte) []byte {
	cs.mu.Lock()
	cs.txCount++
	aead := cs.aead
	cs.mu.Unlock()

	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return aead.Seal(nil, nonce[:], plaintext, ad)
}

func (cs *CipherState) Decrypt(seq uint64, ciphertext, ad []byte) ([]byte, error) {
	cs.mu.RLock()
	aead := cs.aead
	cs.mu.RUnlock()

	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], seq)
	plain, err := aead.Open(nil, nonce[:], ciphertext, ad)
	if err != nil {
		return nil, errors.New("decryption failed or invalid auth tag")
	}
	return plain, nil
}

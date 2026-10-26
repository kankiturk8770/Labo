package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"klink/internal/crypto"
	"klink/internal/obfuscation"
	_ "modernc.org/sqlite"
)

// DeriveUserKey returns a per-user encryption key derived from the server
// master key and the user's session id: HMAC-SHA256(master, session_id). Each
// user therefore encrypts with a distinct key, so a leaked subscription link
// exposes only that one user's traffic — not everyone's. The server recomputes
// it on the fly from the session id in each packet header; nothing is stored.
func DeriveUserKey(master [32]byte, sid [16]byte) [32]byte {
	mac := hmac.New(sha256.New, master[:])
	mac.Write(sid[:])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

type ReplayWindow struct {
	mu      sync.Mutex
	highest uint64
	bitmap  uint64
}

func (rw *ReplayWindow) CheckAndAccept(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if seq == 0 {
		return false
	}
	if seq > rw.highest {
		diff := seq - rw.highest
		if diff >= 64 {
			rw.bitmap = 1
		} else {
			rw.bitmap = (rw.bitmap << diff) | 1
		}
		rw.highest = seq
		return true
	}
	diff := rw.highest - seq
	if diff >= 64 {
		return false
	}
	if (rw.bitmap & (1 << diff)) != 0 {
		return false
	}
	rw.bitmap |= (1 << diff)
	return true
}

type UserSession struct {
	SessionID    [16]byte
	Username     string
	SubToken     string
	TrafficLimit int64
	TrafficUsed  int64
	ExpireTime   time.Time
	MaxDevices   int
	Enabled      bool
	ActiveIP     net.Addr
	LastActive   time.Time
	IsConnected  bool
	Cipher       *crypto.CipherState
	Replay       *ReplayWindow
	txSeq        uint64 // monotonic nonce counter for server->client packets
}

// NextTx returns the next server->client sequence number for this session. It
// is a single monotonic counter across all of the session's streams, so no two
// outbound packets ever reuse an AEAD nonce under the session key.
func (u *UserSession) NextTx() uint64 {
	return atomic.AddUint64(&u.txSeq, 1)
}

type SessionManager struct {
	mu        sync.RWMutex
	sessions  map[[16]byte]*UserSession
	byToken   map[string]*UserSession
	db        *sql.DB
	masterKey [32]byte
}

func NewSessionManager(dbPath string, masterKey [32]byte) (*SessionManager, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		session_id TEXT PRIMARY KEY,
		username TEXT UNIQUE,
		sub_token TEXT UNIQUE,
		traffic_limit INTEGER,
		traffic_used INTEGER,
		expire_unix INTEGER,
		max_devices INTEGER,
		enabled INTEGER DEFAULT 1
	);
	CREATE TABLE IF NOT EXISTS system_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		config_json TEXT
	);`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	sm := &SessionManager{
		sessions:  make(map[[16]byte]*UserSession),
		byToken:   make(map[string]*UserSession),
		db:        db,
		masterKey: masterKey,
	}
	sm.loadFromDB()
	return sm, nil
}

func (sm *SessionManager) SaveDynamicConfig(cfg obfuscation.DynamicConfig) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = sm.db.Exec(`INSERT INTO system_config (id, config_json) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET config_json = excluded.config_json`, string(b))
	return err
}

func (sm *SessionManager) LoadDynamicConfig(defaultDomain string) obfuscation.DynamicConfig {
	var raw string
	err := sm.db.QueryRow("SELECT config_json FROM system_config WHERE id = 1").Scan(&raw)
	if err == nil && raw != "" {
		var cfg obfuscation.DynamicConfig
		if json.Unmarshal([]byte(raw), &cfg) == nil && cfg.MimicDomain != "" {
			return cfg
		}
	}
	cfg := obfuscation.DynamicConfig{
		Profile:      obfuscation.ProfileTLSMimic,
		MimicDomain:  defaultDomain,
		FallbackAddr: defaultDomain + ":443",
		PaddingMax:   64,
	}
	cfg.CertInfo = obfuscation.ProbeTargetTLS(cfg.MimicDomain, cfg.FallbackAddr)
	_ = sm.SaveDynamicConfig(cfg)
	return cfg
}

func (sm *SessionManager) loadFromDB() {
	rows, err := sm.db.Query("SELECT session_id, username, sub_token, traffic_limit, traffic_used, expire_unix, max_devices, enabled FROM users")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var sidHex, username, token string
		var limit, used, expUnix int64
		var maxDev, enabledInt int
		if err := rows.Scan(&sidHex, &username, &token, &limit, &used, &expUnix, &maxDev, &enabledInt); err == nil {
			var sid [16]byte
			b, _ := hex.DecodeString(sidHex)
			copy(sid[:], b)
			cipherState, _ := crypto.NewCipherState(DeriveUserKey(sm.masterKey, sid))
			sess := &UserSession{
				SessionID:    sid,
				Username:     username,
				SubToken:     token,
				TrafficLimit: limit,
				TrafficUsed:  used,
				ExpireTime:   time.Unix(expUnix, 0),
				MaxDevices:   maxDev,
				Enabled:      enabledInt == 1,
				Cipher:       cipherState,
				Replay:       &ReplayWindow{},
			}
			sm.sessions[sid] = sess
			sm.byToken[token] = sess
		}
	}
}

func (sm *SessionManager) CreateUser(username string, limitGB int64, daysValid int, maxDevices int) (*UserSession, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var sid [16]byte
	_, _ = rand.Read(sid[:])
	tokenBytes := make([]byte, 24)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	limitBytes := limitGB * 1024 * 1024 * 1024
	expire := time.Now().Add(time.Duration(daysValid) * 24 * time.Hour)
	sidHex := hex.EncodeToString(sid[:])

	_, err := sm.db.Exec(
		"INSERT INTO users (session_id, username, sub_token, traffic_limit, traffic_used, expire_unix, max_devices, enabled) VALUES (?, ?, ?, ?, 0, ?, ?, 1)",
		sidHex, username, token, limitBytes, expire.Unix(), maxDevices,
	)
	if err != nil {
		return nil, err
	}

	cipherState, _ := crypto.NewCipherState(DeriveUserKey(sm.masterKey, sid))
	sess := &UserSession{
		SessionID:    sid,
		Username:     username,
		SubToken:     token,
		TrafficLimit: limitBytes,
		TrafficUsed:  0,
		ExpireTime:   expire,
		MaxDevices:   maxDevices,
		Enabled:      true,
		Cipher:       cipherState,
		Replay:       &ReplayWindow{},
	}
	sm.sessions[sid] = sess
	sm.byToken[token] = sess
	return sess, nil
}

func (sm *SessionManager) DeleteUser(sidHex string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var sid [16]byte
	b, err := hex.DecodeString(sidHex)
	if err != nil || len(b) != 16 {
		return err
	}
	copy(sid[:], b)
	if sess, ok := sm.sessions[sid]; ok {
		delete(sm.byToken, sess.SubToken)
		delete(sm.sessions, sid)
	}
	_, err = sm.db.Exec("DELETE FROM users WHERE session_id = ?", sidHex)
	return err
}

func (sm *SessionManager) ToggleUser(sidHex string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var sid [16]byte
	b, err := hex.DecodeString(sidHex)
	if err != nil || len(b) != 16 {
		return err
	}
	copy(sid[:], b)
	if sess, ok := sm.sessions[sid]; ok {
		sess.Enabled = !sess.Enabled
		en := 0
		if sess.Enabled {
			en = 1
		}
		_, err = sm.db.Exec("UPDATE users SET enabled = ? WHERE session_id = ?", en, sidHex)
		return err
	}
	return nil
}

func (sm *SessionManager) ResetTraffic(sidHex string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var sid [16]byte
	b, err := hex.DecodeString(sidHex)
	if err != nil || len(b) != 16 {
		return err
	}
	copy(sid[:], b)
	if sess, ok := sm.sessions[sid]; ok {
		sess.TrafficUsed = 0
		_, err = sm.db.Exec("UPDATE users SET traffic_used = 0 WHERE session_id = ?", sidHex)
		return err
	}
	return nil
}

func (sm *SessionManager) ValidateAndMigrate(sessionID [16]byte, seq uint64, bytesAdded int64, currentAddr net.Addr) (*UserSession, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, exists := sm.sessions[sessionID]
	if !exists || !sess.Enabled {
		return nil, false
	}

	if time.Now().After(sess.ExpireTime) || sess.TrafficUsed+bytesAdded > sess.TrafficLimit {
		sess.IsConnected = false
		return nil, false
	}

	if seq > 0 && !sess.Replay.CheckAndAccept(seq) {
		return nil, false
	}

	if currentAddr != nil {
		sess.ActiveIP = currentAddr
	}
	sess.TrafficUsed += bytesAdded
	sess.LastActive = time.Now()
	sess.IsConnected = true
	_ = sess.Cipher.CheckAndRekey()

	return sess, true
}

func (sm *SessionManager) SyncToDB() {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for sid, sess := range sm.sessions {
		sidHex := hex.EncodeToString(sid[:])
		_, _ = sm.db.Exec("UPDATE users SET traffic_used = ? WHERE session_id = ?", sess.TrafficUsed, sidHex)
	}
}

func (sm *SessionManager) GetAllUsers() []*UserSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	list := make([]*UserSession, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		if time.Since(s.LastActive) > 2*time.Minute {
			s.IsConnected = false
		}
		list = append(list, s)
	}
	return list
}

func (sm *SessionManager) GetByToken(token string) (*UserSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.byToken[token]
	return s, ok
}

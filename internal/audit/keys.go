package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Signer signs checkpoints.
type Signer struct {
	key   ed25519.PrivateKey
	keyID string
}

// KeyID derives a short identifier from a public key: the first 16 hex
// characters of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// GenerateKey writes a new Ed25519 private key (PKCS#8 PEM, mode 0600) to
// path and its public key to path+".pub". It refuses to overwrite either
// file: replacing the key would silently orphan earlier checkpoints.
func GenerateKey(path string) (keyID string, err error) {
	pubPath := path + ".pub"
	for _, p := range []string{path, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return "", fmt.Errorf("audit: %s already exists; refusing to overwrite a signing key (key rotation is not supported in v0.1)", p)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("audit: generate key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := writeExclusive(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return "", err
	}
	if err := writeExclusive(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		return "", err
	}
	return KeyID(pub), nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("audit: write %s: %w", path, err)
	}
	return f.Close()
}

// LoadSigner reads a private key written by GenerateKey. A missing key is an
// error; Roro never generates one implicitly.
func LoadSigner(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("audit: signing key %s not found; run `roro init` to create one", path)
		}
		return nil, fmt.Errorf("audit: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("audit: %s is not a PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit: parse %s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("audit: %s is not an Ed25519 key", path)
	}
	return &Signer{key: priv, keyID: KeyID(priv.Public().(ed25519.PublicKey))}, nil
}

// KeyID returns the signer's key id.
func (s *Signer) KeyID() string { return s.keyID }

// Sign signs a checkpoint, filling KeyID and Signature.
func (s *Signer) Sign(c Checkpoint) Checkpoint {
	c.KeyID = s.keyID
	c.Signature = hex.EncodeToString(ed25519.Sign(s.key, c.SignedMessage()))
	return c
}

// LoadPublicKey reads a public key written by GenerateKey.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("audit: %s is not a PEM public key", path)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit: parse %s: %w", path, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("audit: %s is not an Ed25519 key", path)
	}
	return pub, nil
}

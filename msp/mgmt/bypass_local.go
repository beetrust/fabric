package mgmt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/msp"
	mspp "github.com/hyperledger/fabric/protos/msp"
	"github.com/pkg/errors"
)

const bypassIdentityID = "DEFAULT"

func initBypassLocalMSP(mspID string) error {
	if mspID == "" {
		mspID = "BypassMSP"
	}

	bypass, err := newBypassLocalMSP(mspID)
	if err != nil {
		return err
	}

	m.Lock()
	defer m.Unlock()
	localMsp = bypass
	return nil
}

type bypassLocalMSP struct {
	id              string
	signingIdentity *bypassSigningIdentity
}

func newBypassLocalMSP(mspID string) (*bypassLocalMSP, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed generating bypass MSP key")
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   mspID + "-bypass",
			Organization: []string{mspID},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, errors.Wrap(err, "failed creating bypass MSP certificate")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, errors.Wrap(err, "failed parsing bypass MSP certificate")
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	signer := &bypassSigningIdentity{
		identity: bypassIdentity{
			mspID:   mspID,
			certPEM: certPEM,
			cert:    cert,
			pubKey:  &priv.PublicKey,
		},
		privKey: priv,
	}

	return &bypassLocalMSP{
		id:              mspID,
		signingIdentity: signer,
	}, nil
}

func (b *bypassLocalMSP) DeserializeIdentity(serializedIdentity []byte) (msp.Identity, error) {
	sID := &mspp.SerializedIdentity{}
	if err := proto.Unmarshal(serializedIdentity, sID); err != nil {
		return nil, errors.Wrap(err, "could not deserialize identity")
	}

	if sID.Mspid != "" && sID.Mspid != b.id {
		return nil, errors.Errorf("unexpected MSP ID %s, expected %s", sID.Mspid, b.id)
	}

	id := &bypassIdentity{
		mspID:  b.id,
		pubKey: b.signingIdentity.identity.pubKey,
		cert:   b.signingIdentity.identity.cert,
	}

	if len(sID.IdBytes) > 0 {
		id.certPEM = sID.IdBytes
		block, _ := pem.Decode(sID.IdBytes)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				id.cert = cert
				if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
					id.pubKey = pub
				}
			}
		}
	}

	return id, nil
}

func (b *bypassLocalMSP) IsWellFormed(serializedIdentity *mspp.SerializedIdentity) error {
	if serializedIdentity == nil {
		return errors.New("nil identity")
	}
	return nil
}

func (b *bypassLocalMSP) Setup(config *mspp.MSPConfig) error {
	// No-op for bypass MSP.
	return nil
}

func (b *bypassLocalMSP) GetVersion() msp.MSPVersion {
	return msp.MSPv1_4_3
}

func (b *bypassLocalMSP) GetType() msp.ProviderType {
	return msp.FABRIC
}

func (b *bypassLocalMSP) GetIdentifier() (string, error) {
	return b.id, nil
}

func (b *bypassLocalMSP) GetSigningIdentity(identifier *msp.IdentityIdentifier) (msp.SigningIdentity, error) {
	if identifier == nil || identifier.Id == "" || identifier.Id == bypassIdentityID {
		return b.signingIdentity, nil
	}
	return nil, errors.Errorf("unknown identity identifier %s", identifier.Id)
}

func (b *bypassLocalMSP) GetDefaultSigningIdentity() (msp.SigningIdentity, error) {
	return b.signingIdentity, nil
}

func (b *bypassLocalMSP) GetTLSRootCerts() [][]byte {
	return nil
}

func (b *bypassLocalMSP) GetTLSIntermediateCerts() [][]byte {
	return nil
}

func (b *bypassLocalMSP) Validate(id msp.Identity) error {
	return nil
}

func (b *bypassLocalMSP) SatisfiesPrincipal(id msp.Identity, principal *mspp.MSPPrincipal) error {
	return nil
}

type bypassSigningIdentity struct {
	identity bypassIdentity
	privKey  *ecdsa.PrivateKey
}

func (b *bypassSigningIdentity) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, b.privKey, digest[:])
}

func (b *bypassSigningIdentity) GetPublicVersion() msp.Identity {
	pub := b.identity
	return &pub
}

func (b *bypassSigningIdentity) ExpiresAt() time.Time {
	return b.identity.ExpiresAt()
}

func (b *bypassSigningIdentity) GetIdentifier() *msp.IdentityIdentifier {
	return b.identity.GetIdentifier()
}

func (b *bypassSigningIdentity) GetMSPIdentifier() string {
	return b.identity.GetMSPIdentifier()
}

func (b *bypassSigningIdentity) Validate() error {
	return nil
}

func (b *bypassSigningIdentity) GetOrganizationalUnits() []*msp.OUIdentifier {
	return nil
}

func (b *bypassSigningIdentity) Anonymous() bool {
	return false
}

func (b *bypassSigningIdentity) Verify(msg []byte, sig []byte) error {
	return b.identity.Verify(msg, sig)
}

func (b *bypassSigningIdentity) Serialize() ([]byte, error) {
	return b.identity.Serialize()
}

func (b *bypassSigningIdentity) SatisfiesPrincipal(principal *mspp.MSPPrincipal) error {
	return nil
}

type bypassIdentity struct {
	mspID   string
	certPEM []byte
	cert    *x509.Certificate
	pubKey  *ecdsa.PublicKey
}

func (b *bypassIdentity) ExpiresAt() time.Time {
	if b.cert != nil {
		return b.cert.NotAfter
	}
	return time.Time{}
}

func (b *bypassIdentity) GetIdentifier() *msp.IdentityIdentifier {
	return &msp.IdentityIdentifier{
		Mspid: b.mspID,
		Id:    bypassIdentityID,
	}
}

func (b *bypassIdentity) GetMSPIdentifier() string {
	return b.mspID
}

func (b *bypassIdentity) Validate() error {
	return nil
}

func (b *bypassIdentity) GetOrganizationalUnits() []*msp.OUIdentifier {
	return nil
}

func (b *bypassIdentity) Anonymous() bool {
	return false
}

func (b *bypassIdentity) Verify(msg []byte, sig []byte) error {
	if b.pubKey == nil {
		return errors.New("bypass identity missing public key")
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(b.pubKey, digest[:], sig) {
		return errors.New("invalid signature")
	}
	return nil
}

func (b *bypassIdentity) Serialize() ([]byte, error) {
	sID := &mspp.SerializedIdentity{
		Mspid:   b.mspID,
		IdBytes: b.certPEM,
	}
	return proto.Marshal(sID)
}

func (b *bypassIdentity) SatisfiesPrincipal(principal *mspp.MSPPrincipal) error {
	return nil
}

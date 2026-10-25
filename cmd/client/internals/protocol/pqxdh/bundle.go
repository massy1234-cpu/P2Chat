package pqxdh

import (
	"P2Chat/cmd/client/database"
	"P2Chat/cmd/client/internals/commitment"
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	mlkem_keys "P2Chat/cmd/client/internals/keys/mlkem"
	x25519_keys "P2Chat/cmd/client/internals/keys/x25519"
	commitmentproto "P2Chat/cmd/client/internals/proto_generated/commitment/proto_struct_commitment"
	"P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	bundleproto "P2Chat/cmd/client/internals/proto_generated/pqxdh/proto_struct_bundle"
	structures "P2Chat/cmd/client/internals/protocol/pqxdh/structure"
	data "P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/awnumar/memguard"
	"google.golang.org/protobuf/proto"
)

// GetBundleID returns the last local bundle ID in the separate IK database.
func GetBundleID(basePath string) (int, error) {
	return data.LastIKBundleID(basePath)
}

// LoadIKKeys loads and decrypts the identities from the separate IK database.
func LoadIKKeys(password *memguard.Enclave, basePath string, ID int) (*IdentityKeys, error) {

	keys, err := data.LoadIKKeys(basePath, ID)
	if err != nil {
		return nil, apperr.Wrap("load IK keys", err)
	}
	sk, pk, ik := keys.PrivateMLDSA, keys.PublicMLDSA, keys.PrivateX25519
	if len(sk) < 4000 || len(pk) < 2000 || len(ik) < 50 {
		return nil, apperr.New("stored IK size check failed")
	}

	// decrypt ML-DSA private key (Argon2id or HSM handled internally)
	skStruct := &proto_struct_mldsa.PrivateKeyMLDSA{}
	if err := proto.Unmarshal(sk, skStruct); err != nil {
		return nil, apperr.Wrap("unmarshal ML-DSA private IK", err)
	}

	privateMLDSA, err := mldsa_keys.DecodePrivateKey(password, skStruct)
	if err != nil {
		return nil, apperr.Wrap("decrypt ML-DSA private key", err)
	}

	// public ML-DSA key - NOT encrypted
	pkStruct := &proto_struct_mldsa.PublicKeyMLDSA{}
	if err := proto.Unmarshal(pk, pkStruct); err != nil {
		return nil, apperr.Wrap("unmarshal ML-DSA public IK", err)
	}
	publicMLDSA, err := mldsa_keys.DecodePublicKey(pkStruct)
	if err != nil {
		return nil, apperr.Wrap("decode ML-DSA public IK", err)
	}

	// decrypt X25519 IK private key
	privateX25519, err := x25519_keys.DecryptPrivateKey(password, ik)
	if err != nil {
		return nil, apperr.Wrap("decrypt X25519 IK", err)
	}

	return &IdentityKeys{PrivateMLDSA: privateMLDSA, PublicMLDSA: publicMLDSA, PrivateX25519: privateX25519}, nil

}

// GeneratedBundles holds the generated public and private components of a PQXDH bundle.
type GeneratedBundles struct {
	Public            *bundleproto.PublicBundle
	Private           *structures.PrivateBundle
	PrivateCommitment *commitmentproto.CommitmentSchemePrivate
}

// InitializedPQXDH holds the complete public package to upload to the server.
type InitializedPQXDH struct {
	PublicBundle    *bundleproto.PublicBundle
	CurvePublicSets []*bundleproto.CurveSet
	KemPublicSets   []*bundleproto.PqkemSet
}

// CreateBundles assembles the public and private PQXDH bundles.
// password is an Argon2-derived AES-256 key, managed at a higher level.
// ML-DSA and X25519 IK keys are stored in a separate per-bundle database bucket;
// SPK and ML-KEM private keys are encrypted and stored in the private bundle.
func CreateBundles(password *memguard.Enclave, commitmentSecret *memguard.Enclave, bundleLevel int, commitmentLevel int, HSM bool, ID int) (*GeneratedBundles, error) {
	return createBundles(password, commitmentSecret, bundleLevel, commitmentLevel, HSM, data.BasePath, ID)
}

func createBundles(password *memguard.Enclave, commitmentSecret *memguard.Enclave, bundleLevel int, commitmentLevel int, HSM bool, basePath string, ID int) (*GeneratedBundles, error) {
	if ID < 0 || int64(ID) > 1<<31-1 {
		return nil, apperr.New("invalid local bundle ID")
	}
	if bundleLevel < 1 || bundleLevel > 3 {
		return nil, apperr.New("bundle Argon level must be between 1 and 3")
	}
	if commitmentLevel < 1 || commitmentLevel > 3 {
		return nil, apperr.New("commitment Argon level must be between 1 and 3")
	}

	public := &bundleproto.PublicBundle{}
	private := &structures.PrivateBundle{}

	public.Id = int32(ID)
	private.ID = ID

	keys := &data.IKKeys{}

	privateKeyMldsa, publicKeyMldsa, err := FillMLDSA(password, bundleLevel, HSM, public, keys)
	if err != nil {
		return nil, err
	}

	ikEnclave, err := FillXeddsa(password, bundleLevel, HSM, public, private, keys)
	if err != nil {
		return nil, err
	}

	if err := fillLastResortPQKEM(password, bundleLevel, HSM, public, private); err != nil {
		return nil, err
	}

	// cross-sign IK keys: ML-DSA signs IK_X25519, X25519 signs IK_mldsa
	public.IkX25519Signed, err = privateKeyMldsa.Sign(public.GetIkX25519(), nil, true)
	if err != nil {
		return nil, apperr.Wrap("error during the ML-DSA signature of IK_X25519", err)
	}

	public.IkMldsaSigned, err = ikEnclave.Sign(public.GetIkMldsa())
	if err != nil {
		return nil, apperr.Wrap("error during the X25519 signature of IK_mldsa", err)
	}

	public.SpkSigned, err = privateKeyMldsa.Sign(public.GetSpk(), nil, true)
	if err != nil {
		return nil, apperr.Wrap("error during the ML-DSA signature of SPK", err)
	}

	public.LastResortPqkemSigned, err = privateKeyMldsa.Sign(public.GetLastResortPqkem(), nil, true)
	if err != nil {
		return nil, apperr.Wrap("error during the ML-DSA signature of last-resort PQKEM", err)
	}

	var privateCommitment *commitmentproto.CommitmentSchemePrivate
	public.CommitmentScheme, privateCommitment, err = commitment.Commitment(publicKeyMldsa, ikEnclave.PublicKey(), privateKeyMldsa, ikEnclave, commitmentSecret, commitmentLevel, password, bundleLevel, HSM)
	if err != nil {
		return nil, apperr.Wrap("create bundle commitment", err)
	}

	if err := data.SaveIKKeys(basePath, ID, *keys); err != nil {
		return nil, apperr.Wrap("save bundle IK keys", err)
	}
	return &GeneratedBundles{
		Public:            public,
		Private:           private,
		PrivateCommitment: privateCommitment,
	}, nil
}

// FillMLDSA fills the public identity and prepares the encrypted storage records.
func FillMLDSA(password *memguard.Enclave, level int, HSM bool, public *bundleproto.PublicBundle, keys *data.IKKeys) (privateKeyMldsa *mldsa_keys.PrivateMLDSA, publicKeyMldsa *mldsa_keys.PublicMLDSA, err error) {

	privateKeyMldsa, rawPub, err := mldsa_keys.CreateKeys()
	if err != nil {
		return nil, nil, apperr.Wrap("error during the creation of the bundle for pqxdh (mldsa) ", err)
	}

	privStruct, err := privateKeyMldsa.Encrypt(password, level, HSM)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the encryption of the mldsa bundle key", err)
	}

	pubStruct, err := rawPub.Serialize()
	if err != nil {
		return nil, nil, apperr.Wrap("error during the creation of the public key struct", err)
	}

	public.IkMldsa = pubStruct.Key

	if err := privStruct.SetChecksum(); err != nil {
		return nil, nil, err
	}
	if err := pubStruct.SetChecksum(); err != nil {
		return nil, nil, err
	}
	keys.PrivateMLDSA, err = proto.Marshal(privStruct)
	if err != nil {
		return nil, nil, apperr.Wrap("marshal ML-DSA private IK", err)
	}
	keys.PublicMLDSA, err = proto.Marshal(pubStruct)
	if err != nil {
		return nil, nil, apperr.Wrap("marshal ML-DSA public IK", err)
	}

	return privateKeyMldsa, rawPub, nil

}

// fill the public bundle with X25519 IK and SPK, encrypt private keys in the private bundle.
// The encrypted X25519 IK is prepared for the separate identity database.
func FillXeddsa(password *memguard.Enclave, level int, HSM bool, public *bundleproto.PublicBundle, private *structures.PrivateBundle, keys *data.IKKeys) (ikEnclave *x25519_keys.PrivateX25519, err error) {

	ikEnclave, ikPub, err := x25519_keys.CreateKey()
	if err != nil {
		return nil, apperr.Wrap("create X25519 IK", err)
	}
	public.IkX25519 = ikPub.Bytes()

	ikSerialized, err := ikEnclave.SerializeAndEncrypt(password, level, HSM)
	if err != nil {
		return nil, apperr.Wrap("serialize IK X25519", err)
	}

	keys.PrivateX25519 = ikSerialized

	spkEnclave, spkPub, err := x25519_keys.CreateKey()
	if err != nil {
		return nil, apperr.Wrap("create SPK", err)
	}
	id, err := newPrekeyID()
	if err != nil {
		return nil, err
	}
	public.SpkId, private.SPKID = id, int(id)
	public.Spk = spkPub.Bytes()

	private.SPK, err = spkEnclave.SerializeAndEncrypt(password, level, HSM)
	if err != nil {
		return nil, apperr.Wrap("serialize SPK", err)
	}

	return ikEnclave, nil
}

func newPrekeyID() (int32, error) {
	id, err := rand.Int(rand.Reader, big.NewInt(1<<31-1))
	if err != nil {
		return 0, apperr.Wrap("generate prekey identifier", err)
	}
	return int32(id.Int64() + 1), nil
}

func fillLastResortPQKEM(password *memguard.Enclave, level int, HSM bool, public *bundleproto.PublicBundle, private *structures.PrivateBundle) error {
	pqkemEnclave, pqkemPub, err := mlkem_keys.CreateKey()
	if err != nil {
		return apperr.Wrap("create ML-KEM last resort key", err)
	}
	id, err := newPrekeyID()
	if err != nil {
		return err
	}
	public.LastResortId, private.LastResortID = id, int(id)
	public.LastResortPqkem = pqkemPub.Bytes()

	scheme, err := pqkemEnclave.Encrypt(password, level, HSM)
	if err != nil {
		return apperr.Wrap("encrypt PQKEM", err)
	}

	private.Last_resort_PQKEM, err = mlkem_keys.SerializePrivateKey(scheme)
	if err != nil {
		return apperr.Wrap("serialize PQKEM", err)
	}

	return nil
}

// create the private and public set curve (only one)
// i manage the creation and the fill in one function, infact these type of set are less important than the main bundle
// i can do a trade-off in this case for create a more compact code and efficent
// *this function will manage from another that will create a stock of 100 CurveSet*
// all the sensitive data inside the struct are encrypted inside this function using the 'EncryptPrivateKey' function
func CreateCurveSet(privateKeyMldsa *mldsa_keys.PrivateMLDSA, privateKeyX25519 *x25519_keys.PrivateX25519, password *memguard.Enclave, level int, HSM bool, identifier int) (privateSet []byte, publicSet *bundleproto.CurveSet, err error) {

	private := &structures.PrivateCurveSet{}
	public := &bundleproto.CurveSet{}

	private.Identifier = identifier
	public.Identifier = int32(identifier)

	privateEnclaved, publicKey, err := x25519_keys.CreateKey()
	if err != nil {
		return nil, nil, apperr.Wrap("error during creation of X25519 keys", err)
	}

	public.X25519Key = publicKey.Bytes()

	private.Key = privateEnclaved

	public.SignatureMldsa, err = privateKeyMldsa.Sign(public.X25519Key, nil, true)
	if err != nil {
		return nil, nil, apperr.Wrap("error during mldsa signature in the curve set", err)
	}

	public.SignatureX25519, err = privateKeyX25519.Sign(public.X25519Key)
	if err != nil {
		return nil, nil, apperr.Wrap("error during x25519 signature in the curve set", err)
	}

	privateBytes, err := private.SerializeAndEncrypt(password, level, HSM)
	if err != nil {
		return nil, nil, apperr.Wrap("serialize private curve set", err)
	}

	return privateBytes, public, nil
}

// all the sensitive data inside the struct are encrypted inside this function using the 'EncryptPrivateKey' function
func CreatePQKEMSet(privateKeyMldsa *mldsa_keys.PrivateMLDSA, privateKeyX25519 *x25519_keys.PrivateX25519, password *memguard.Enclave, level int, HSM bool, identifier int) (privateSet []byte, publicSet *bundleproto.PqkemSet, err error) {

	private := &structures.PrivatekemSet{}
	public := &bundleproto.PqkemSet{}

	private.Identifier = identifier
	public.Identifier = int32(identifier)

	privateEnclaved, publicKey, err := mlkem_keys.CreateKey()
	if err != nil {
		return nil, nil, apperr.Wrap("error during creation of ML-KEM keys", err)
	}

	public.PqkemKey = publicKey.Bytes()

	private.Key = privateEnclaved

	public.SignatureMldsa, err = privateKeyMldsa.Sign(public.PqkemKey, nil, true)
	if err != nil {
		return nil, nil, apperr.Wrap("error during mldsa signature in the PQKEM set", err)
	}

	public.SignatureX25519, err = privateKeyX25519.Sign(public.PqkemKey)
	if err != nil {
		return nil, nil, apperr.Wrap("error during x25519 signature in the PQKEM set", err)
	}

	privateBytes, err := private.SerializeAndEncrypt(password, level, HSM)
	if err != nil {
		return nil, nil, apperr.Wrap("serialize private PQKEM set", err)
	}

	return privateBytes, public, nil
}

// CreateCurveSets creates curve sets in memory.
// Returns the private serialized sets and the public protobuf sets.
// NOTE : the set is divided into public and private part, only the public must be published onto the server, the private must be saved into database
func CreateCurveSets(password *memguard.Enclave, level int, HSM bool, basePath string, ID int, numSets int) (privateSets [][]byte, publicSets []*bundleproto.CurveSet, err error) {

	identity, err := LoadIKKeys(password, basePath, ID)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the load of the IK keys", err)
	}

	privateSets = make([][]byte, numSets)
	publicSets = make([]*bundleproto.CurveSet, numSets)

	for i := 0; i < numSets; i++ {
		privateSet, publicSet, err := CreateCurveSet(identity.PrivateMLDSA, identity.PrivateX25519, password, level, HSM, i)
		if err != nil {
			return nil, nil, apperr.Wrap("error during the creation of the sets", err)
		}

		privateSets[i] = privateSet
		publicSets[i] = publicSet
	}

	return privateSets, publicSets, nil
}

// CreateKEMSets creates ml-kem sets in memory.
// Returns the slice of pairs (serialized to bytes) ready to be saved by the caller.
// NOTE : the set is divided into public and private part, only the public must be published onto the server, the private must be saved into database
func CreateKEMsets(password *memguard.Enclave, level int, HSM bool, basePath string, ID int, numSets int) (privateSets [][]byte, publicSets []*bundleproto.PqkemSet, err error) {

	identity, err := LoadIKKeys(password, basePath, ID)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the load of the IK keys", err)
	}

	privateSets = make([][]byte, numSets)
	publicSets = make([]*bundleproto.PqkemSet, numSets)

	for i := 0; i < numSets; i++ {
		privateSet, publicSet, err := CreatePQKEMSet(identity.PrivateMLDSA, identity.PrivateX25519, password, level, HSM, i)
		if err != nil {
			return nil, nil, apperr.Wrap("error during the creation of the PQKEM sets", err)
		}

		privateSets[i] = privateSet
		publicSets[i] = publicSet
	}

	return privateSets, publicSets, nil
}

// main function that manage all the bundle generation flow
func InitializePQXDH(password *memguard.Enclave, commitmentSecret *memguard.Enclave, bundleLevel int, commitmentLevel int, HSM bool, basePath string, numSets int) (*InitializedPQXDH, error) {

	// get the right ID
	currentID, err := GetBundleID(basePath)
	if err != nil {
		return nil, apperr.Wrap("load last IK bundle ID", err)
	}

	// new bundle ID
	newID := currentID + 1

	// flow : create the main bundles ( private and public ), the public will send to the server and the
	// private saved on the device
	bundles, err := createBundles(password, commitmentSecret, bundleLevel, commitmentLevel, HSM, basePath, newID)
	if err != nil {
		return nil, apperr.Wrap("error during the creation of the bundle", err)
	}

	// create curve and kem sets
	curvePrivateSet, curvePublicSet, err := CreateCurveSets(password, bundleLevel, HSM, basePath, newID, numSets)
	if err != nil {
		return nil, apperr.Wrap("error during the creation of the curve sets", err)
	}

	kemPrivateSet, kemPublicSet, err := CreateKEMsets(password, bundleLevel, HSM, basePath, newID, numSets)
	if err != nil {
		return nil, apperr.Wrap("error during the creation of the KEM sets", err)
	}
	h1 := sha256.Sum256(bundles.Public.IkX25519)
	h2 := sha256.Sum256(bundles.Public.IkMldsa)
	bundleID := sha256.Sum256(append(h1[:], h2[:]...))

	// save the private part of the sets
	if err := database.SaveSets(curvePrivateSet, bundleID[:], "curve"); err != nil {
		return nil, apperr.Wrap("error during save the curve set: ", err)
	}
	if err := database.SaveSets(kemPrivateSet, bundleID[:], "kem"); err != nil {
		return nil, apperr.Wrap("error during save the kem set: ", err)
	}

	// i have NOT to destroy all the sets bytes because are already encrypted, so safe in memory

	// save the privateBundle struct inside the database ( SPK and last-resort key )
	if err := database.SavePrivateBundle(bundles.Private, bundleID[:]); err != nil {
		return nil, apperr.Wrap("error during save the curve set: ", err)
	}
	if err := database.SaveCommitment(bundles.PrivateCommitment, bundleID[:]); err != nil {
		return nil, apperr.Wrap("error during save the private commitment: ", err)
	}

	// this is safe, the GC will not collect the [][]byte, this data will be send to the server
	return &InitializedPQXDH{
		PublicBundle:    bundles.Public,
		CurvePublicSets: curvePublicSet,
		KemPublicSets:   kemPublicSet,
	}, nil
}

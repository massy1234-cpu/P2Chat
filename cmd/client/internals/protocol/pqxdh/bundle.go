package pqxdh

import (
	"P2Chat/cmd/client/database"
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	mlkem_keys "P2Chat/cmd/client/internals/keys/mlkem"
	x25519_keys "P2Chat/cmd/client/internals/keys/x25519"
	"P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	bundleproto "P2Chat/cmd/client/internals/proto_generated/pqxdh/proto_struct_bundle"
	structures "P2Chat/cmd/client/internals/protocol/pqxdh/structure"
	data "P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"github.com/awnumar/memguard"
	messagepack "github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/proto"
)

// bundleIKDir returns the filesystem path for the IK keys of a given bundle.
// Example: <BasePath>/bundle_3_IK_keys
func bundleIKDir(id int) string {
	return filepath.Join(data.BasePath, "bundle_"+strconv.Itoa(id)+"_IK_keys")
}

// GetBundleID want as parameter the /data directory
func GetBundleID(basePath string) (int, error) {
	ls, err := os.ReadDir(basePath)
	if err != nil {
		return -1, apperr.Wrap("error during fetch the directory", err)
	}

	maxID := -1
	for _, e := range ls {
		if e.IsDir() && strings.HasPrefix(e.Name(), "bundle_") && strings.HasSuffix(e.Name(), "_IK_keys") {
			parts := strings.Split(e.Name(), "_")
			if len(parts) < 3 {
				continue
			}
			num, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			if num > maxID {
				maxID = num
			}
		}
	}

	if maxID != -1 {
		return maxID, nil
	}

	return -1, apperr.New("there are no IK keys directories in the base path")
}


// LoadIKKeys loads the IK keys stored outside the database ( ML-DSA and X25519 )
func LoadIKKeys(password *memguard.Enclave, basePath string, ID int) (privateMLDSA *memguard.Enclave, publicMLDSA *proto_struct_mldsa.PublicKeyMLDSA, privateX25519 *memguard.Enclave, err error) {

	ikDir := filepath.Join(basePath, "bundle_"+strconv.Itoa(ID)+"_IK_keys")

	// for ML-DSA i have to save also the public key because i removed the seed of the private for security reasons
	var sk, pk, ik []byte

	entries, err := os.ReadDir(ikDir)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("read IK keys directory", err)
	}

	for _, e := range entries {
		fullPath := filepath.Join(ikDir, e.Name())
		switch e.Name() {
		case "SK.bin":
			sk, err = os.ReadFile(fullPath)
		case "PK.bin":
			pk, err = os.ReadFile(fullPath)
		case "IK_X25519.bin":
			ik, err = os.ReadFile(fullPath)
		}
		if err != nil {
			return nil, nil, nil, apperr.Wrap("read "+e.Name(), err)
		}
	}

	if len(sk) < 4000 || len(pk) < 2000 || len(ik) < 50 {
		return nil, nil, nil, apperr.New("file size check failed for IK keys")
	}

	// decrypt ML-DSA private key (Argon2id or HSM handled internally)
	skStruct := &proto_struct_mldsa.PrivateKeyMLDSA{}
	if err := proto.Unmarshal(sk, skStruct); err != nil {
		return nil, nil, nil, apperr.Wrap("unmarshal SK.bin", err)
	}

	privateMLDSA, err = mldsa_keys.DecodePrivateKey(password, skStruct)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("decrypt ML-DSA private key", err)
	}

	// public ML-DSA key - NOT encrypted
	pkStruct := &proto_struct_mldsa.PublicKeyMLDSA{}
	if err := proto.Unmarshal(pk, pkStruct); err != nil {
		return nil, nil, nil, apperr.Wrap("unmarshal PK.bin", err)
	}
	publicMLDSA = pkStruct

	// decrypt X25519 IK private key
	privateX25519, err = x25519_keys.DecryptPrivateKey(password, ik)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("decrypt X25519 IK", err)
	}

	return privateMLDSA, publicMLDSA, privateX25519, nil

}

// CreateBundles assembles the public and private PQXDH bundles.
// password is an Argon2-derived AES-256 key, managed at a higher level.
// ML-DSA and X25519 IK keys are stored on filesystem in a per-bundle directory;
// SPK and ML-KEM private keys are encrypted and stored in the private bundle.
func CreateBundles(password *memguard.Enclave, level int, HSM bool, ID int) (public *bundleproto.PublicBundle, private *structures.PrivateBundle, err error) {

	public = &bundleproto.PublicBundle{}
	private = &structures.PrivateBundle{}

	public.Id = int32(ID)
	private.ID = ID

	ikDir := bundleIKDir(ID)

	privateKeyMldsa, err := FillMLDSA(password, level, HSM, public, ikDir)
	if err != nil {
		return nil, nil, err
	}

	ikEnclave, err := FillXeddsa(password, HSM, public, private, ikDir)
	if err != nil {
		return nil, nil, err
	}

	if err := fillLastResortPQKEM(password, HSM, public, private); err != nil {
		return nil, nil, err
	}

	// cross-sign IK keys: ML-DSA signs IK_X25519, X25519 signs IK_mldsa
	public.IkX25519Signed, err = mldsa_keys.Sign(privateKeyMldsa, public.GetIkX25519(), nil, true)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the ML-DSA signature of IK_X25519", err)
	}

	public.IkMldsaSigned, err = x25519_keys.Sign(ikEnclave, public.GetIkMldsa())
	if err != nil {
		return nil, nil, apperr.Wrap("error during the X25519 signature of IK_mldsa", err)
	}

	public.SpkSigned, err = mldsa_keys.Sign(privateKeyMldsa, public.GetSpk(), nil, true)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the ML-DSA signature of SPK", err)
	}

	public.LastResortPqkemSigned, err = mldsa_keys.Sign(privateKeyMldsa, public.GetLastResortPqkem(), nil, true)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the ML-DSA signature of last-resort PQKEM", err)
	}

	return public, private, nil
}


// fill the public bundle with MLDSA and store keys in the bundle IK directory
func FillMLDSA(password *memguard.Enclave, level int, HSM bool, public *bundleproto.PublicBundle, ikDir string) (privateKeyMldsa *memguard.Enclave, err error) {

	privateKeyStruct, publicKeyStruct, privateKeyMldsa, err := mldsa_keys.CreateKeys(level, password, HSM)
	if err != nil {
		return nil, apperr.Wrap("error during the creation of the bundle for pqxdh (mldsa) ", err)
	}

	public.IkMldsa = publicKeyStruct.Key

	if err := mldsa_keys.StoreKeys(privateKeyStruct, publicKeyStruct, ikDir); err != nil {
		return nil, apperr.Wrap("store ML-DSA keys in bundle dir", err)
	}

	return privateKeyMldsa, nil

}

// fill the public bundle with X25519 IK and SPK, encrypt private keys in the private bundle.
// The X25519 IK private key is encrypted and saved on filesystem in the per-bundle IK directory.
// password is an Argon2-derived AES-256 key — already derived at a higher level
func FillXeddsa(password *memguard.Enclave, HSM bool, public *bundleproto.PublicBundle, private *structures.PrivateBundle, ikDir string) (ikEnclave *memguard.Enclave, err error) {

	ikEnclave, ikPub, err := x25519_keys.CreateKey()
	if err != nil {
		return nil, apperr.Wrap("create X25519 IK", err)
	}
	public.IkX25519 = ikPub.Bytes()

	ikScheme, err := x25519_keys.EncryptPrivateKey(password, ikEnclave, HSM)
	if err != nil {
		return nil, apperr.Wrap("encrypt IK X25519", err)
	}

	ikSerialized, err := x25519_keys.SerializePrivateKey(ikScheme)
	if err != nil {
		return nil, apperr.Wrap("serialize IK X25519", err)
	}

	if err := data.SaveBytesOnFile(ikSerialized, ikDir, "IK_X25519.bin"); err != nil {
		return nil, apperr.Wrap("save IK X25519 private key", err)
	}

	spkEnclave, spkPub, err := x25519_keys.CreateKey()
	if err != nil {
		return nil, apperr.Wrap("create SPK", err)
	}
	public.Spk = spkPub.Bytes()

	spkScheme, err := x25519_keys.EncryptPrivateKey(password, spkEnclave, HSM)
	if err != nil {
		return nil, apperr.Wrap("encrypt SPK", err)
	}

	private.SPK, err = x25519_keys.SerializePrivateKey(spkScheme)
	if err != nil {
		return nil, apperr.Wrap("serialize SPK", err)
	}

	return ikEnclave, nil
}

// password is an Argon2-derived AES-256 key — already derived at a higher level
func fillLastResortPQKEM(password *memguard.Enclave, HSM bool, public *bundleproto.PublicBundle, private *structures.PrivateBundle) error {
	pqkemEnclave, pqkemPub, err := mlkem_keys.CreateKey()
	if err != nil {
		return apperr.Wrap("create ML-KEM last resort key", err)
	}
	public.LastResortPqkem = pqkemPub.Bytes()

	scheme, err := mlkem_keys.EncryptPrivateKey(password, pqkemEnclave, HSM)
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
func CreateCurveSet(privateKeyMldsa *memguard.Enclave,privateKeyX25519 *memguard.Enclave, password *memguard.Enclave, HSM bool, identifier int) (privateSet []byte, publicSet []byte, err error) {

	private := &structures.PrivateCurveSet{}
	public := &bundleproto.CurveSet{}

	private.Identifier = identifier
	public.Identifier = int32(identifier)

	privateEnclaved,publicKey,err := x25519_keys.CreateKey()
	if err != nil {
		return nil,nil,apperr.Wrap("error during creation of X25519 keys",err)
	}

	public.X25519Key = publicKey.Bytes()

	privateEncrypted, err := x25519_keys.EncryptPrivateKey(password, privateEnclaved, HSM)
	if err != nil {
		return nil,nil,apperr.Wrap("encrypt SPK", err)
	}
	private.X25519_key, err = x25519_keys.SerializePrivateKey(privateEncrypted)
	if err != nil {
		return nil,nil,apperr.Wrap("serialize SPK", err)
	}

	public.SignatureMldsa,err = mldsa_keys.Sign(privateKeyMldsa,public.X25519Key,nil,true)
	if err != nil {
		return nil,nil,apperr.Wrap("error during mldsa signature in the curve set",err)
	}
	
	public.SignatureX25519,err = x25519_keys.Sign(privateKeyX25519,public.X25519Key)
	if err != nil {
		return nil,nil,apperr.Wrap("error during x25519 signature in the curve set",err)
	}

	privateBytes, err := messagepack.Marshal(private)
	if err != nil {
		return nil,nil,apperr.Wrap("marshal private curve set", err)
	}

	publicBytes, err := proto.Marshal(public)
	if err != nil {
		return nil,nil,apperr.Wrap("marshal public curve set", err)
	}

	return privateBytes, publicBytes, nil
}


// all the sensitive data inside the struct are encrypted inside this function using the 'EncryptPrivateKey' function
func CreatePQKEMSet(privateKeyMldsa *memguard.Enclave,privateKeyX25519 *memguard.Enclave, password *memguard.Enclave, HSM bool, identifier int) (privateSet []byte, publicSet []byte, err error) {

	private := &structures.PrivatekemSet{}
	public := &bundleproto.PqkemSet{}

	private.Identifier = identifier
	public.Identifier = int32(identifier)

	privateEnclaved,publicKey,err := mlkem_keys.CreateKey()
	if err != nil {
		return nil,nil,apperr.Wrap("error during creation of ML-KEM keys",err)
	}

	public.PqkemKey = publicKey.Bytes()

	privateEncrypted, err := mlkem_keys.EncryptPrivateKey(password, privateEnclaved, HSM)
	if err != nil {
		return nil,nil,apperr.Wrap("encrypt ML-KEM", err)
	}
	private.Pqkem_key, err = mlkem_keys.SerializePrivateKey(privateEncrypted)
	if err != nil {
		return nil,nil,apperr.Wrap("serialize PQKEM", err)
	}

	public.SignatureMldsa,err = mldsa_keys.Sign(privateKeyMldsa,public.PqkemKey,nil,true)
	if err != nil {
		return nil,nil,apperr.Wrap("error during mldsa signature in the PQKEM set",err)
	}
	
	public.SignatureX25519,err = x25519_keys.Sign(privateKeyX25519,public.PqkemKey)
	if err != nil {
		return nil,nil,apperr.Wrap("error during x25519 signature in the PQKEM set",err)
	}

	privateBytes, err := messagepack.Marshal(private)
	if err != nil {
		return nil,nil,apperr.Wrap("marshal private PQKEM set", err)
	}

	publicBytes, err := proto.Marshal(public)
	if err != nil {
		return nil,nil,apperr.Wrap("marshal public PQKEM set", err)
	}

	return privateBytes, publicBytes, nil
}


// CreateCurveSets creates curve sets in memory.
// Returns the slice of pairs (serialized to bytes) ready to be saved by the caller.
// NOTE : the set is divided into public and private part, only the public must be published onto the server, the private must be saved into database
func CreateCurveSets(password *memguard.Enclave, HSM bool, basePath string, ID int, numSets int) (privateSets [][]byte, publicSets [][]byte, err error) {

	privateMLDSA, _, privateX25519, err := LoadIKKeys(password, basePath, ID)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the load of the IK keys", err)
	}

	privateSets = make([][]byte, numSets)
	publicSets = make([][]byte, numSets)

	for i := 0; i < numSets; i++ {
		privateSet, publicSet, err := CreateCurveSet(privateMLDSA, privateX25519, password, HSM, i)
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
func CreateKEMsets(password *memguard.Enclave, HSM bool, basePath string, ID int, numSets int) (privateSets [][]byte, publicSets [][]byte, err error) {

	privateMLDSA, _, privateX25519, err := LoadIKKeys(password, basePath, ID)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the load of the IK keys", err)
	}

	privateSets = make([][]byte, numSets)
	publicSets = make([][]byte, numSets)

	for i := 0; i < numSets; i++ {
		privateSet, publicSet, err := CreatePQKEMSet(privateMLDSA, privateX25519, password, HSM, i)
		if err != nil {
			return nil, nil, apperr.Wrap("error during the creation of the PQKEM sets", err)
		}

		privateSets[i] = privateSet
		publicSets[i] = publicSet
	}

	return privateSets, publicSets, nil
}



// main function that manage all the bundle generation flow
func InitializePQXDH(password *memguard.Enclave, level int, HSM bool, basePath string, numSets int) (publicBundle *bundleproto.PublicBundle,curvePublicSets [][]byte ,kemPublicSets [][]byte, err error) {
	
	// get the right ID
	currentID, err := GetBundleID(basePath)
	if err != nil {
		currentID = -1
	}

	// new bundle ID
	newID := currentID + 1

	ID := strconv.Itoa(newID)

	// flow : create the main bundles ( private and public ), the public will send to the server and the 
	// private saved on the device
	publicBundle, privateBundle, err := CreateBundles(password, level, HSM, newID)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("error during the creation of the bundle", err)
	}

	// create curve and kem sets
	curvePrivateSet, curvePublicSet, err := CreateCurveSets(password, HSM, basePath, newID, numSets)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("error during the creation of the curve sets", err)
	}

	kemPrivateSet, kemPublicSet, err := CreateKEMsets(password, HSM, basePath, newID, numSets)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("error during the creation of the KEM sets", err)
	}

	// save the private part of the sets
	if err := database.SaveSets(curvePrivateSet,"curve:"+ID);err != nil {
		return nil,nil,nil,apperr.Wrap("error during save the curve set: ",err)
	}
	if err:= database.SaveSets(kemPrivateSet,"kem:"+ID);err != nil {
		return nil,nil,nil,apperr.Wrap("error during save the kem set: ",err)
	}

	// i have NOT to destroy all the sets bytes because are already encrypted, so safe in memory

	// save the privateBundle struct inside the database ( SPK and last-resort key )
	if err := database.SavePrivateBundle(privateBundle,ID);err != nil {
		return nil,nil,nil,apperr.Wrap("error during save the curve set: ",err)
	}
	
	// this is safe, the GC will not collect the [][]byte, this data will be send to the server
	return publicBundle,curvePublicSet,kemPublicSet,nil
}
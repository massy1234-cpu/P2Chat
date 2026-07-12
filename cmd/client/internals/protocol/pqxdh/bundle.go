package pqxdh

import (
	"P2Chat/cmd/client/database"
	"P2Chat/cmd/client/internals/argon"
	hsm "P2Chat/cmd/client/internals/encryption/encryption_hsm"
	mldsa_keys "P2Chat/cmd/client/internals/keys/mldsa"
	mlkem_keys "P2Chat/cmd/client/internals/keys/mlkem"
	x25519_keys "P2Chat/cmd/client/internals/keys/x25519"
	"P2Chat/cmd/client/internals/proto_generated/mldsa/proto_struct_mldsa"
	structures "P2Chat/cmd/client/internals/protocol/pqxdh/structure"
	data "P2Chat/cmd/client/internals/storage"
	"P2Chat/pkg/apperr"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	messagepack "github.com/vmihailenco/msgpack/v5"
	"github.com/awnumar/memguard"
	"google.golang.org/protobuf/proto"
)

// bundleIKDir returns the filesystem path for the IK keys of a given bundle.
// Example: <BasePath>/bundle_3_IK_keys
func bundleIKDir(id int) string {
	return filepath.Join(data.BasePath, "bundle_"+strconv.Itoa(id)+"_IK_keys")
}

// must pass the /data directory
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


func loadIKKeys(password *memguard.Enclave, basePath string) (privateMLDSA *memguard.Enclave, publicMLDSA *proto_struct_mldsa.PublicKeyMLDSA, privateX25519 *memguard.Enclave, err error) {

	num, err := GetBundleID(basePath)
	if err != nil {
		return nil, nil, nil, apperr.Wrap("error during getting the ID bundle", err)
	}

	ikDir := filepath.Join(basePath, "bundle_"+strconv.Itoa(num)+"_IK_keys")

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

	// decrypt ML-DSA private key
	skStruct := &proto_struct_mldsa.PrivateKeyMLDSA{}
	if err := proto.Unmarshal(sk, skStruct); err != nil {
		return nil, nil, nil, apperr.Wrap("unmarshal SK.bin", err)
	}

	// check if the private key ML-DSA was encrypted with an HSM
	if skStruct.HsmMethod != 0 {
		plaintext, err := hsm.DecryptHSM(password, skStruct.Key, skStruct.Nonce, int(skStruct.HsmMethod))
		if err != nil {
			return nil, nil, nil, apperr.Wrap("decrypt ML-DSA private key with HSM", err)
		}
		privateMLDSA = memguard.NewEnclave(plaintext.Bytes())
		plaintext.Destroy()
	} else {
		pwdBuf, err := password.Open()
		if err != nil {
			return nil, nil, nil, apperr.Wrap("open password enclave", err)
		}
		defer pwdBuf.Destroy()

		aesKey, err := argon.HashWithArgon(int(skStruct.ArgonParams.Level), pwdBuf, skStruct.ArgonParams.Salt)
		if err != nil {
			return nil, nil, nil, apperr.Wrap("derive argon key for ML-DSA", err)
		}
		defer aesKey.Destroy()

		privateMLDSA, err = mldsa_keys.DecodePrivateKey(skStruct, aesKey, int(skStruct.ArgonParams.Level), skStruct.ArgonParams.Salt)
		if err != nil {
			return nil, nil, nil, apperr.Wrap("decrypt ML-DSA private key", err)
		}
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
func CreateBundles(password *memguard.Enclave, level int, HSM bool, ID int) (public *structures.PqxdhPublicBundle, private *structures.PqxdhPrivateBundle, err error) {

	public = &structures.PqxdhPublicBundle{}
	private = &structures.PqxdhPrivateBundle{}

	public.ID = ID
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
	public.IK_X25519_signed, err = mldsa_keys.Sign(privateKeyMldsa, public.IK_X25519, nil, true)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the ML-DSA signature of IK_X25519", err)
	}

	public.IK_mldsa_signed, err = x25519_keys.Sign(ikEnclave, public.IK_mldsa)
	if err != nil {
		return nil, nil, apperr.Wrap("error during the X25519 signature of IK_mldsa", err)
	}

	return public, private, nil
}


// fill the public bundle with MLDSA and store keys in the bundle IK directory
func FillMLDSA(password *memguard.Enclave, level int, HSM bool, public *structures.PqxdhPublicBundle, ikDir string) (privateKeyMldsa *memguard.Enclave, err error) {

	privateKeyStruct, publicKeyStruct, privateKeyMldsa, err := mldsa_keys.CreateKeys(level, password, false, HSM)
	if err != nil {
		return nil, apperr.Wrap("error during the creation of the bundle for pqxdh (mldsa) ", err)
	}

	public.IK_mldsa = publicKeyStruct.Key

	if err := mldsa_keys.StoreKeys(privateKeyStruct, publicKeyStruct, ikDir); err != nil {
		return nil, apperr.Wrap("store ML-DSA keys in bundle dir", err)
	}

	return privateKeyMldsa, nil

}

// fill the public bundle with X25519 IK and SPK, encrypt private keys in the private bundle.
// The X25519 IK private key is encrypted and saved on filesystem in the per-bundle IK directory.
// password is an Argon2-derived AES-256 key — already derived at a higher level
func FillXeddsa(password *memguard.Enclave, HSM bool, public *structures.PqxdhPublicBundle, private *structures.PqxdhPrivateBundle, ikDir string) (ikEnclave *memguard.Enclave, err error) {

	ikEnclave, ikPub, err := x25519_keys.CreateKey()
	if err != nil {
		return nil, apperr.Wrap("create X25519 IK", err)
	}
	public.IK_X25519 = ikPub.Bytes()

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
	public.SPK = spkPub.Bytes()

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
func fillLastResortPQKEM(password *memguard.Enclave, HSM bool, public *structures.PqxdhPublicBundle, private *structures.PqxdhPrivateBundle) error {
	pqkemEnclave, pqkemPub, err := mlkem_keys.CreateKey()
	if err != nil {
		return apperr.Wrap("create ML-KEM last resort key", err)
	}
	public.Last_resort_PQKEM = pqkemPub.Bytes()

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
// *this function will manage from another that will create a stock of 100 structures.CurveSet*
func CreateCurveSet(privateKeyMldsa *memguard.Enclave,privateKeyX25519 *memguard.Enclave, password *memguard.Enclave, HSM bool, identifier int) (privateSet *structures.PrivateCurveSet, publicSet *structures.CurveSet,err error) {

	privateSet = &structures.PrivateCurveSet{}
	publicSet = &structures.CurveSet{}

	privateSet.Identifier = identifier
	publicSet.Identifier = identifier

	privateEnclaved,public,err := x25519_keys.CreateKey()
	if err != nil {
		return nil,nil,apperr.Wrap("error during creation of X25519 keys",err)
	}

	publicSet.X25519_key = public.Bytes()					// simple serialization

	// encryption and serialization of the private key
	privateEncrypted, err := x25519_keys.EncryptPrivateKey(password, privateEnclaved, HSM)
	if err != nil {
		return nil,nil,apperr.Wrap("encrypt SPK", err)
	}
	privateSet.X25519_key, err = x25519_keys.SerializePrivateKey(privateEncrypted)
	if err != nil {
		return nil,nil,apperr.Wrap("serialize SPK", err)
	}

	// hybrid signature ( mldsa + x25519 )
	publicSet.Signature_mldsa,err = mldsa_keys.Sign(privateKeyMldsa,publicSet.X25519_key,nil,true)
	if err != nil {
		return nil,nil,apperr.Wrap("error during mldsa signature in the curve set",err)
	}
	
	publicSet.Signature_x25519,err = x25519_keys.Sign(privateKeyX25519,publicSet.X25519_key)
	if err != nil {
		return nil,nil,apperr.Wrap("error during x25519 signature in the curve set",err)
	}

	return privateSet,publicSet,nil
}




func CreatePQKEMSet(privateKeyMldsa *memguard.Enclave,privateKeyX25519 *memguard.Enclave, password *memguard.Enclave, HSM bool, identifier int) (privateSet *structures.PrivatekemSet, publicSet *structures.PqkemSet,err error) {

	privateSet = &structures.PrivatekemSet{}
	publicSet = &structures.PqkemSet{}

	privateSet.Identifier = identifier
	publicSet.Identifier = identifier

	privateEnclaved,public,err := mlkem_keys.CreateKey()
	if err != nil {
		return nil,nil,apperr.Wrap("error during creation of X25519 keys",err)
	}

	publicSet.Pqkem_key = public.Bytes()					// simple serialization

	// encryption and serialization of the private key
	privateEncrypted, err := mlkem_keys.EncryptPrivateKey(password, privateEnclaved, HSM)
	if err != nil {
		return nil,nil,apperr.Wrap("encrypt ML-KEM", err)
	}
	privateSet.Pqkem_key, err = mlkem_keys.SerializePrivateKey(privateEncrypted)
	if err != nil {
		return nil,nil,apperr.Wrap("serialize SPK", err)
	}

	// hybrid signature ( mldsa + x25519 )
	publicSet.Signature_mldsa,err = mldsa_keys.Sign(privateKeyMldsa,publicSet.Pqkem_key,nil,true)
	if err != nil {
		return nil,nil,apperr.Wrap("error during mldsa signature in the curve set",err)
	}
	
	publicSet.Signature_x25519,err = x25519_keys.Sign(privateKeyX25519,publicSet.Pqkem_key)
	if err != nil {
		return nil,nil,apperr.Wrap("error during x25519 signature in the curve set",err)
	}

	return privateSet,publicSet,nil
}


// CreateCurveSets creates numSets curve sets in memory.
// Returns the slice of pairs (serialized to bytes) ready to be saved by the caller.
func CreateCurveSets(password *memguard.Enclave, HSM bool, basePath string, numSets int) ([]structures.SetPair, error) {

	privateMLDSA, _, privateX25519, err := loadIKKeys(password, basePath)
	if err != nil {
		return nil, apperr.Wrap("error during the load of the IK keys", err)
	}

	pairs := make([]structures.SetPair, numSets)

	for i := 0; i < numSets; i++ {
		privateSet, publicSet, err := CreateCurveSet(privateMLDSA, privateX25519, password, HSM, i)
		if err != nil {
			return nil, apperr.Wrap("error during the creation of the sets", err)
		}

		privateBytes, err := messagepack.Marshal(privateSet)
		if err != nil {
			return nil, apperr.Wrap("marshal private curve set", err)
		}

		publicBytes, err := messagepack.Marshal(publicSet)
		if err != nil {
			return nil, apperr.Wrap("marshal public curve set", err)
		}

		pairs[i] = structures.SetPair{
			Private: privateBytes,
			Public:  publicBytes,
		}
	}

	return pairs, nil
}


func CreateKEMsets(password *memguard.Enclave, HSM bool, basePath string, numSets int) ([]structures.SetPair, error) {

	privateMLDSA, _, privateX25519, err := loadIKKeys(password, basePath)
	if err != nil {
		return nil, apperr.Wrap("error during the load of the IK keys", err)
	}

	pairs := make([]structures.SetPair, numSets)

	for i := 0; i < numSets; i++ {
		privateSet, publicSet, err := CreatePQKEMSet(privateMLDSA, privateX25519, password, HSM, i)
		if err != nil {
			return nil, apperr.Wrap("error during the creation of the PQKEM sets", err)
		}

		privateBytes, err := messagepack.Marshal(privateSet)
		if err != nil {
			return nil, apperr.Wrap("marshal private KEM set", err)
		}

		publicBytes, err := messagepack.Marshal(publicSet)
		if err != nil {
			return nil, apperr.Wrap("marshal public KEM set", err)
		}

		pairs[i] = structures.SetPair{
			Private: privateBytes,
			Public:  publicBytes,
		}
	}

	return pairs, nil
}

// main function that manage all the bundle generation flow
func InitializePQXDH(password *memguard.Enclave, level int, HSM bool, basePath string, numSets int) (publicBundle *structures.PqxdhPrivateBundle,err error) {

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
	privateBundle, publicBundle, err := CreateBundles(password, level, HSM, newID)
	if err != nil {
		return -1, nil, nil, apperr.Wrap("error during the creation of the bundle", err)
	}

	// these sets have to be stored in the local database
	curvePairs, err := CreateCurveSets(password, HSM, basePath, numSets)
	if err != nil {
		return -1, nil, nil, apperr.Wrap("error during the creation of the curve sets", err)
	}

	kemPairs, err := CreateKEMsets(password, HSM, basePath, numSets)
	if err != nil {
		return -1, nil, nil, apperr.Wrap("error during the creation of the KEM sets", err)
	}

	// save the private part of the sets
	database.SaveSets(curvePairs,ID)
	database.SaveSets(kemPairs,ID)

	database.SaveSets()
}
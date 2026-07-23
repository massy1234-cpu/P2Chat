package structures

// bundle that the user publish on the server, are all bytes because
// the server doesn't need to process this data, it have only to understand
// what send and send it
type PublicBundle struct {
	ID 						int
	IK_mldsa 				[]byte		// public key
	IK_mldsa_signed			[]byte
	IK_X25519				[]byte		// public key
	IK_X25519_signed		[]byte
	SPK 					[]byte		// type : x25519
	SPK_signed				[]byte
	Last_resort_PQKEM		[]byte		// type : ML-KEM
	Last_resort_PQKEM_signed []byte
}

// private bundle stored in the database. IK_MLDSA is NOT here:
// it lives on filesystem as SK.bin with its own encryption layer
// (Argon2id + AES-256-GCM) and is referenced by ID when needed
type PrivateBundle struct {
	ID 						int
	SPK 					[]byte
	Last_resort_PQKEM		[]byte
}

// sets to store on the device
type PrivateCurveSet struct {
	Identifier 		int
	X25519_key 		[]byte
}

// if pqkem_key is null, i will get the last resort in the database bucket
type PrivatekemSet struct {
	Identifier 		int
	Pqkem_key 		[]byte
}

// set to publish with the bundle
type CurveSet struct {
	Identifier 			int
	X25519_key 			[]byte
	Signature_mldsa 	[]byte
	Signature_x25519 	[]byte
}

type PqkemSet struct {
	Identifier 			int
	Pqkem_key 			[]byte
	Signature_mldsa 	[]byte
	Signature_x25519 	[]byte
}

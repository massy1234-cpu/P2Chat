package structures

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

package pqxdh

// bundle that the user have to publish on the server, are all bytes because
// the server doesn't need to process this data, it have only to understand
// what send and send it
type pqxdhPublicBundle struct {
	ID 							int
	IK_mldsa 					[]byte
	IK_mldsa_signed				[]byte
	IK_X25519					[]byte
	IK_X25519_signed			[]byte
	SPK 						[]byte
	SPK_signed					[]byte
	Last_resort_PQKEM			[]byte
	Last_resort_PQKEM_signed	[]byte
}

// this is the bundle that contains the respetive private keys
// of the public bundle on the server. This type of bundle is saved into
// the database
type pqxdhPrivateBundle struct {
	ID 							int
	IK_mldsa 					[]byte
	IK_X25519					[]byte
	SPK 						[]byte
	Last_resort_PQKEM			[]byte
}

// sets to store on the device
type PrivateCurveSet struct {
	Identifier 			int
	x25519_key 			[]byte
	signature 			[]byte
}

type PrivatePqkemSet struct {
	Identifier 			int
	pqkem_key 			[]byte
	signature 			[]byte
}

// set to publish with the bundle
type curveSet struct {
	Identifier 			int
	x25519_key 			[]byte
	signature 			[]byte
}

type pqkemSet struct {
	Identifier 			int
	pqkem_key 			[]byte
	signature 			[]byte
}


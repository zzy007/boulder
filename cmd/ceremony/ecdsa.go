package main

import (
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"log"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/miekg/pkcs11"
)

var stringToCurve = map[string]elliptic.Curve{
	sm2.P256Sm2().Params().Name	: sm2.P256Sm2(),
	elliptic.P224().Params().Name: elliptic.P224(),
	elliptic.P256().Params().Name: elliptic.P256(),
	elliptic.P384().Params().Name: elliptic.P384(),
	elliptic.P521().Params().Name: elliptic.P521(),
}

// curveToOIDDER maps the name of the curves to their DER encoded OIDs
var curveToOIDDER = map[string]asn1.ObjectIdentifier{
	sm2.P256Sm2().Params().Name	:  {1, 2, 156, 10197, 1, 301},
	elliptic.P224().Params().Name: {1, 3, 132, 0, 33}, //{6, 5, 43, 129, 4, 0, 33},
	elliptic.P256().Params().Name: {1, 2, 840, 10045, 3, 1, 7},//{6, 8, 42, 134, 72, 206, 61, 3, 1, 7},
	elliptic.P384().Params().Name: {1, 3, 132, 0, 34}, // {6, 5, 43, 129, 4, 0, 34},
	elliptic.P521().Params().Name: {1, 3, 132, 0, 35},//{6, 5, 43, 129, 4, 0, 35},
}


var curveToHash = map[elliptic.Curve]sm2.Hash{
	elliptic.P224(): sm2.SHA256,
	elliptic.P256(): sm2.SHA256,
	elliptic.P384(): sm2.SHA384,
	elliptic.P521(): sm2.SHA512,
	sm2.P256Sm2()	:sm2.SM3,
}

var hashToString = map[sm2.Hash]string{
	sm2.SM3	  : "SM3",
	sm2.SHA256: "SHA-256",
	sm2.SHA384: "SHA-384",
	sm2.SHA512: "SHA-512",
}

// ecArgs constructs the private and public key template attributes sent to the
// device and specifies which mechanism should be used. curve determines which
// type of key should be generated.
func ecArgs(label string, curve elliptic.Curve, keyID []byte) generateArgs {
	pencodedCurve := curveToOIDDER[curve.Params().Name]
	encodedCurve, _ := asn1.Marshal(pencodedCurve)
	log.Printf("\tEncoded curve parameters for %s: %X\n", curve.Params().Name, encodedCurve)
	return generateArgs{
		mechanism: []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_IBM_SM2_KEY_PAIR_GEN, nil),
		},
		publicAttrs: []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedCurve),
		},
		privateAttrs: []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			// Prevent attributes being retrieved
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			// Prevent the key being extracted from the device
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			// Allow the key to sign data
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		},
	}
}

// ecPub extracts the generated public key, specified by the provided object
// handle, and constructs an ecdsa.PublicKey. It also checks that the key is of
// the correct curve type.
func ecPub(
	session *pkcs11helpers.Session,
	object pkcs11.ObjectHandle,
	expectedCurve elliptic.Curve,
) (*sm2.PublicKey, error) {
	pubKey, err := session.GetECDSAPublicKey(object)
	if err != nil {
		return nil, err
	}
	if pubKey.Curve != expectedCurve {
		return nil, errors.New("Returned EC parameters doesn't match expected curve")
	}
	log.Printf("\tX: %X\n", pubKey.X.Bytes())
	log.Printf("\tY: %X\n", pubKey.Y.Bytes())
	return pubKey, nil
}

// ecGenerate is used to generate and verify a ECDSA key pair of the type
// specified by curveStr and with the provided label. It returns the public
// part of the generated key pair as a ecdsa.PublicKey and the random key ID
// that the HSM uses to identify the key pair.
func ecGenerate(session *pkcs11helpers.Session, label, curveStr string) (*sm2.PublicKey, []byte, error) {
	curve, present := stringToCurve[curveStr]
	if !present {
		return nil, nil, fmt.Errorf("curve %q not supported", curveStr)
	}
	keyID := make([]byte, 4)
	_, err := newRandReader(session).Read(keyID)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("[zzy-debug ceremony ecdsa 112]Generating SM2 key with curve %s and ID %x\n", curveStr, keyID)
	args := ecArgs(label, curve, keyID)
	pub, _, err := session.GenerateKeyPair(args.mechanism, args.publicAttrs, args.privateAttrs)
	if err != nil {
		return nil, nil, fmt.Errorf("[zzy-debug ceremony ecdsa 118] err", err)
	}
	log.Println("Key generated")
	log.Println("Extracting public key")
	pk, err := ecPub(session, pub, curve)
	if err != nil {
		return nil, nil, err
	}
	log.Println("Extracted public key")
	return pk, keyID, nil
}

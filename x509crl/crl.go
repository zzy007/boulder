// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This code is copied from the Go 1.15 tree, and includes
// the CRL generation functionality introduced in CL 217298.
// Once we transition to 1.15 this code can be deleted.

package x509crl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"io"
	"math/big"
	"time"
)

// RevocationList contains the fields used to create an X.509 v2 Certificate
// Revocation list with CreateRevocationList.
type RevocationList struct {
	// SignatureAlgorithm is used to determine the signature algorithm to be
	// used when signing the CRL. If 0 the default algorithm for the signing
	// key will be used.
	SignatureAlgorithm sm2.SignatureAlgorithm

	// RevokedCertificates is used to populate the revokedCertificates
	// sequence in the CRL, it may be empty. RevokedCertificates may be nil,
	// in which case an empty CRL will be created.
	RevokedCertificates []pkix.RevokedCertificate

	// Number is used to populate the X.509 v2 cRLNumber extension in the CRL,
	// which should be a monotonically increasing sequence number for a given
	// CRL scope and CRL issuer.
	Number *big.Int
	// ThisUpdate is used to populate the thisUpdate field in the CRL, which
	// indicates the issuance date of the CRL.
	ThisUpdate time.Time
	// NextUpdate is used to populate the nextUpdate field in the CRL, which
	// indicates the date by which the next CRL will be issued. NextUpdate
	// must be greater than ThisUpdate.
	NextUpdate time.Time
	// ExtraExtensions contains any additional extensions to add directly to
	// the CRL.
	ExtraExtensions []pkix.Extension
}

var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureSM2WithSM3      = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	oidSignatureSM2WithSHA1     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}
	oidSignatureSM2WithSHA256   = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 503}
	//	oidSignatureSM3WithRSA      = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 504}

	oidSM3     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 1}
	oidSHA256  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidHashSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)

var signatureAlgorithmDetails = []struct {
	algo       sm2.SignatureAlgorithm
	oid        asn1.ObjectIdentifier
	pubKeyAlgo sm2.PublicKeyAlgorithm
	hash       sm2.Hash
}{
	{sm2.MD2WithRSA, oidSignatureMD2WithRSA, sm2.RSA, sm2.Hash(0) /* no value for MD2 */},
	{sm2.MD5WithRSA, oidSignatureMD5WithRSA, sm2.RSA, sm2.MD5},
	{sm2.SHA1WithRSA, oidSignatureSHA1WithRSA, sm2.RSA, sm2.SHA1},
	{sm2.SHA1WithRSA, oidISOSignatureSHA1WithRSA, sm2.RSA, sm2.SHA1},
	{sm2.SHA256WithRSA, oidSignatureSHA256WithRSA, sm2.RSA, sm2.SHA256},
	{sm2.SHA384WithRSA, oidSignatureSHA384WithRSA, sm2.RSA, sm2.SHA384},
	{sm2.SHA512WithRSA, oidSignatureSHA512WithRSA, sm2.RSA, sm2.SHA512},
	{sm2.SHA256WithRSAPSS, oidSignatureRSAPSS, sm2.RSA, sm2.SHA256},
	{sm2.SHA384WithRSAPSS, oidSignatureRSAPSS, sm2.RSA, sm2.SHA384},
	{sm2.SHA512WithRSAPSS, oidSignatureRSAPSS, sm2.RSA, sm2.SHA512},
	{sm2.DSAWithSHA1, oidSignatureDSAWithSHA1, sm2.DSA, sm2.SHA1},
	{sm2.DSAWithSHA256, oidSignatureDSAWithSHA256, sm2.DSA, sm2.SHA256},
	{sm2.ECDSAWithSHA1, oidSignatureECDSAWithSHA1, sm2.ECDSA, sm2.SHA1},
	{sm2.ECDSAWithSHA256, oidSignatureECDSAWithSHA256, sm2.ECDSA, sm2.SHA256},
	{sm2.ECDSAWithSHA384, oidSignatureECDSAWithSHA384, sm2.ECDSA, sm2.SHA384},
	{sm2.ECDSAWithSHA512, oidSignatureECDSAWithSHA512, sm2.ECDSA, sm2.SHA512},
	{sm2.SM2WithSM3, oidSignatureSM2WithSM3, sm2.ECDSA, sm2.SM3},
	{sm2.SM2WithSHA1, oidSignatureSM2WithSHA1, sm2.ECDSA, sm2.SHA1},
	{sm2.SM2WithSHA256, oidSignatureSM2WithSHA256, sm2.ECDSA, sm2.SHA256},
	//	{SM3WithRSA, oidSignatureSM3WithRSA, RSA, SM3},
}


// signingParamsForPublicKey returns the parameters to use for signing with
// priv. If requestedSigAlgo is not zero then it overrides the default
// signature algorithm.
func signingParamsForPublicKey(pub interface{}, requestedSigAlgo sm2.SignatureAlgorithm) (hashFunc sm2.Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType sm2.PublicKeyAlgorithm

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubType = sm2.RSA
		hashFunc = sm2.SHA256
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		sigAlgo.Parameters = asn1.NullRawValue

	case *ecdsa.PublicKey:
		pubType = sm2.ECDSA

		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = sm2.SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = sm2.SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = sm2.SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}

	case *sm2.PublicKey:
		pubType = sm2.ECDSA
		switch pub.Curve {
		case sm2.P256Sm2():
			hashFunc = sm2.SM3
			sigAlgo.Algorithm = oidSignatureSM2WithSM3
		default:
			err = errors.New("x509: unknown SM2 curve")
		}
	default:
		err = errors.New("x509: only RSA, ECDSA and Ed25519 keys supported")
	}

	if err != nil {
		return
	}

	if requestedSigAlgo == 0 {
		return
	}

	found := false
	for _, details := range signatureAlgorithmDetails {
		if details.algo == requestedSigAlgo {
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
			if hashFunc == 0 {
				err = errors.New("x509: cannot sign with hash function requested")
				return
			}
			// FORK NOTE: we don't use PSS so rather than pulling in this code,
			// which requires locally redefining x509.SignatureAlgorithm, we just
			// comment it out.
			// if requestedSigAlgo.isRSAPSS() {
			// 	sigAlgo.Parameters = rsaPSSParameters(hashFunc)
			// }
			found = true
			break
		}
	}

	if !found {
		err = errors.New("x509: unknown SignatureAlgorithm")
	}

	return
}

// RFC 5280,  4.2.1.1
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionCRLNumber             = []int{2, 5, 29, 20}
)

// CreateRevocationList creates a new X.509 v2 Certificate Revocation List,
// according to RFC 5280, based on template.
//
// The CRL is signed by priv which should be the private key associated with
// the public key in the issuer certificate.
//
// The issuer may not be nil, and the crlSign bit must be set in KeyUsage in
// order to use it as a CRL issuer.
//
// The issuer distinguished name CRL field and authority key identifier
// extension are populated using the issuer certificate. issuer must have
// SubjectKeyId set.
func CreateRevocationList(rand io.Reader, template *RevocationList, issuer *sm2.Certificate, priv crypto.Signer) ([]byte, error) {
	if template == nil {
		return nil, errors.New("x509: template can not be nil")
	}
	if issuer == nil {
		return nil, errors.New("x509: issuer can not be nil")
	}
	if (issuer.KeyUsage & sm2.KeyUsageCRLSign) == 0 {
		return nil, errors.New("x509: issuer must have the crlSign key usage bit set")
	}
	if len(issuer.SubjectKeyId) == 0 {
		return nil, errors.New("x509: issuer certificate doesn't contain a subject key identifier")
	}
	if template.NextUpdate.Before(template.ThisUpdate) {
		return nil, errors.New("x509: template.ThisUpdate is after template.NextUpdate")
	}
	if template.Number == nil {
		return nil, errors.New("x509: template contains nil Number field")
	}

	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(priv.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	// Force revocation times to UTC per RFC 5280.
	revokedCertsUTC := make([]pkix.RevokedCertificate, len(template.RevokedCertificates))
	for i, rc := range template.RevokedCertificates {
		rc.RevocationTime = rc.RevocationTime.UTC()
		revokedCertsUTC[i] = rc
	}

	aki, err := asn1.Marshal(authKeyId{Id: issuer.SubjectKeyId})
	if err != nil {
		return nil, err
	}
	crlNum, err := asn1.Marshal(template.Number)
	if err != nil {
		return nil, err
	}

	tbsCertList := pkix.TBSCertificateList{
		Version:    1, // v2
		Signature:  signatureAlgorithm,
		Issuer:     issuer.Subject.ToRDNSequence(),
		ThisUpdate: template.ThisUpdate.UTC(),
		NextUpdate: template.NextUpdate.UTC(),
		Extensions: []pkix.Extension{
			{
				Id:    oidExtensionAuthorityKeyId,
				Value: aki,
			},
			{
				Id:    oidExtensionCRLNumber,
				Value: crlNum,
			},
		},
	}
	if len(revokedCertsUTC) > 0 {
		tbsCertList.RevokedCertificates = revokedCertsUTC
	}

	if len(template.ExtraExtensions) > 0 {
		tbsCertList.Extensions = append(tbsCertList.Extensions, template.ExtraExtensions...)
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return nil, err
	}

	input := tbsCertListContents
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(tbsCertListContents)
		input = h.Sum(nil)
	}
	var signerOpts crypto.SignerOpts = hashFunc
	// FORK NOTE: we don't use PSS so rather than pulling in this code,
	// which requires locally redefining x509.SignatureAlgorithm, we just
	// comment it out.
	// if template.SignatureAlgorithm.isRSAPSS() {
	// 	signerOpts = &rsa.PSSOptions{
	// 		SaltLength: rsa.PSSSaltLengthEqualsHash,
	// 		Hash:       hashFunc,
	// 	}
	// }

	signature, err := priv.Sign(rand, input, signerOpts)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(pkix.CertificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

package cmd

import (
"crypto"
"crypto/ecdsa"
"crypto/elliptic"
"crypto/rand"
"crypto/rsa"
"crypto/x509/pkix"
"encoding/asn1"
"encoding/base64"
"errors"
"fmt"
"github.com/letsencrypt/boulder/akamai"
"github.com/tjfoc/gmsm/sm2"
"math/big"
"time"
)

// Response represents an OCSP response containing a single SingleResponse. See
// RFC 6960.
type Response struct {
	// Status is one of {Good, Revoked, Unknown}
	Status                                        int
	SerialNumber                                  *big.Int
	ProducedAt, ThisUpdate, NextUpdate, RevokedAt time.Time
	RevocationReason                              int
	Certificate                                   *sm2.Certificate
	// TBSResponseData contains the raw bytes of the signed response. If
	// Certificate is nil then this can be used to verify Signature.
	TBSResponseData    []byte
	Signature          []byte
	SignatureAlgorithm sm2.SignatureAlgorithm

	// IssuerHash is the hash used to compute the IssuerNameHash and IssuerKeyHash.
	// Valid values are crypto.SHA1, crypto.SHA256, crypto.SHA384, and crypto.SHA512.
	// If zero, the default is crypto.SHA1.
	IssuerHash sm2.Hash

	// RawResponderName optionally contains the DER-encoded subject of the
	// responder certificate. Exactly one of RawResponderName and
	// ResponderKeyHash is set.
	RawResponderName []byte
	// ResponderKeyHash optionally contains the SHA-1 hash of the
	// responder's public key. Exactly one of RawResponderName and
	// ResponderKeyHash is set.
	ResponderKeyHash []byte

	// Extensions contains raw X.509 extensions from the singleExtensions field
	// of the OCSP response. When parsing certificates, this can be used to
	// extract non-critical extensions that are not parsed by this package. When
	// marshaling OCSP responses, the Extensions field is ignored, see
	// ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any marshaled
	// OCSP response (in the singleExtensions field). Values override any
	// extensions that would otherwise be produced based on the other fields. The
	// ExtraExtensions field is not populated when parsing certificates, see
	// Extensions.
	ExtraExtensions []pkix.Extension
}

var idPKIXOCSPBasic = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 7, 48, 1, 1})

type ResponseStatus int

const (
	Success       ResponseStatus = 0
	Malformed     ResponseStatus = 1
	InternalError ResponseStatus = 2
	TryLater      ResponseStatus = 3
	// Status code four is unused in OCSP. See
	// https://tools.ietf.org/html/rfc6960#section-4.2.1
	SignatureRequired ResponseStatus = 5
	Unauthorized      ResponseStatus = 6
)


// The status values that can be expressed in OCSP.  See RFC 6960.
const (
	// Good means that the certificate is valid.
	Good = iota
	// Revoked means that the certificate has been deliberately revoked.
	Revoked
	// Unknown means that the OCSP responder doesn't know about the certificate.
	Unknown
	// ServerFailed is unused and was never used (see
	// https://go-review.googlesource.com/#/c/18944). ParseResponse will
	// return a ResponseError when an error response is parsed.
	ServerFailed
)

type responseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []singleResponse
}

type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}
type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}


type singleResponse struct {
	CertID           certID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          revokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
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


func CreateResponse(issuer, responderCert *sm2.Certificate, template Response, priv crypto.Signer) ([]byte, error) {
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, err
	}

	if template.IssuerHash == 0 {
		template.IssuerHash = sm2.SHA1
	}
	hashOID := akamai.GetOIDFromHashAlgorithm(template.IssuerHash)
	if hashOID == nil {
		return nil, errors.New("unsupported issuer hash algorithm")
	}

	if !template.IssuerHash.Available() {
		return nil, fmt.Errorf("issuer hash algorithm %v not linked into binary", template.IssuerHash)
	}
	h := template.IssuerHash.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	innerResponse := singleResponse{
		CertID: certID{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  hashOID,
				Parameters: asn1.RawValue{Tag: 5 /* ASN.1 NULL */},
			},
			NameHash:      issuerNameHash,
			IssuerKeyHash: issuerKeyHash,
			SerialNumber:  template.SerialNumber,
		},
		ThisUpdate:       template.ThisUpdate.UTC(),
		NextUpdate:       template.NextUpdate.UTC(),
		SingleExtensions: template.ExtraExtensions,
	}

	switch template.Status {
	case Good:
		innerResponse.Good = true
	case Unknown:
		innerResponse.Unknown = true
	case Revoked:
		innerResponse.Revoked = revokedInfo{
			RevocationTime: template.RevokedAt.UTC(),
			Reason:         asn1.Enumerated(template.RevocationReason),
		}
	}

	rawResponderID := asn1.RawValue{
		Class:      2, // context-specific
		Tag:        1, // Name (explicit tag)
		IsCompound: true,
		Bytes:      responderCert.RawSubject,
	}
	tbsResponseData := responseData{
		Version:        0,
		RawResponderID: rawResponderID,
		ProducedAt:     time.Now().Truncate(time.Minute).UTC(),
		Responses:      []singleResponse{innerResponse},
	}

	tbsResponseDataDER, err := asn1.Marshal(tbsResponseData)
	if err != nil {
		return nil, err
	}

	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(priv.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	responseHash := hashFunc.New()
	responseHash.Write(tbsResponseDataDER)
	signature, err := priv.Sign(rand.Reader, responseHash.Sum(nil), hashFunc)
	if err != nil {
		return nil, err
	}

	response := basicResponse{
		TBSResponseData:    tbsResponseData,
		SignatureAlgorithm: signatureAlgorithm,
		Signature: asn1.BitString{
			Bytes:     signature,
			BitLength: 8 * len(signature),
		},
	}
	if template.Certificate != nil {
		response.Certificates = []asn1.RawValue{
			{FullBytes: template.Certificate.Raw},
		}
	}
	responseDER, err := asn1.Marshal(response)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(responseASN1{
		Status: asn1.Enumerated(Success),
		Response: responseBytes{
			ResponseType: idPKIXOCSPBasic,
			Response:     responseDER,
		},
	})
}


// TODO(rlb): This is also from crypto/x509, so same comment as AGL's below
func signingParamsForPublicKey(pub interface{}, requestedSigAlgo sm2.SignatureAlgorithm) (hashFunc sm2.Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType sm2.PublicKeyAlgorithm

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubType = sm2.RSA
		hashFunc = sm2.SHA256
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		sigAlgo.Parameters = asn1.RawValue{
			Tag: 5,
		}

	case *ecdsa.PublicKey:
		pubType = sm2.ECDSA

		switch pub.Curve {
		case sm2.P256Sm2():
			hashFunc = sm2.SM3
			sigAlgo.Algorithm = oidSignatureSM2WithSM3
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
			err = errors.New("[zzy-debug ceremony ocsp]x509: unknown elliptic curve")
		}

	default:
		err = errors.New("[zzy-debug ceremony ocsp]x509: only RSA and ECDSA keys supported")
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
				err = errors.New("[zzy-debug ceremony ocsp]x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
			if hashFunc == 0 {
				err = errors.New("[zzy-debug ceremony ocsp]x509: cannot sign with hash function requested")
				return
			}
			found = true
			break
		}
	}

	if !found {
		err = errors.New("x509: unknown SignatureAlgorithm")
	}

	return
}

func generateOCSPResponse(signer crypto.Signer, issuer, delegatedIssuer, cert *sm2.Certificate, thisUpdate, nextUpdate time.Time, status int) ([]byte, error) {
	//if err := cert.CheckSignatureFrom(issuer); err != nil {
	//	return nil, fmt.Errorf("invalid signature on certificate from issuer: %s", err)
	//}

	signingCert := issuer
	if delegatedIssuer != nil {
		signingCert = delegatedIssuer
		//if err := delegatedIssuer.CheckSignatureFrom(issuer); err != nil {
		//	return nil, fmt.Errorf("invalid signature on delegated issuer from issuer: %s", err)
		//}

		gotOCSPEKU := false
		for _, eku := range delegatedIssuer.ExtKeyUsage {
			if eku == sm2.ExtKeyUsageOCSPSigning {
				gotOCSPEKU = true
				break
			}
		}
		if !gotOCSPEKU {
			return nil, errors.New("delegated issuer certificate doesn't contain OCSPSigning extended key usage")
		}
	}

	if nextUpdate.Before(thisUpdate) {
		return nil, errors.New("thisUpdate must be before nextUpdate")
	}
	if thisUpdate.Before(signingCert.NotBefore) {
		return nil, errors.New("thisUpdate is before signing certificate's notBefore")
	} else if nextUpdate.After(signingCert.NotAfter) {
		return nil, errors.New("nextUpdate is after signing certificate's notAfter")
	}

	template := Response{
		SerialNumber: cert.SerialNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		Status:       status,
	}
	if delegatedIssuer != nil {
		template.Certificate = delegatedIssuer
	}

	resp, err := CreateResponse(issuer, signingCert, template, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create response: %s", err)
	}

	encodedResp := make([]byte, base64.StdEncoding.EncodedLen(len(resp))+1)
	base64.StdEncoding.Encode(encodedResp, resp)
	encodedResp[len(encodedResp)-1] = '\n'

	return encodedResp, nil
}

package helper

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"io"
	"io/ioutil"
	"math/big"
	//"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
	"github.com/http"
)

var (
	method             = flag.String("method", "GET", "Method to use for fetching OCSP")
	urlOverride        = flag.String("url", "", "URL of OCSP responder to override")
	hostOverride       = flag.String("host", "", "Host header to override in HTTP request")
	tooSoon            = flag.Int("too-soon", 76, "If NextUpdate is fewer than this many hours in future, warn.")
	ignoreExpiredCerts = flag.Bool("ignore-expired-certs", false, "If a cert is expired, don't bother requesting OCSP.")
	expectStatus       = flag.Int("expect-status", -1, "Expect response to have this numeric status (0=Good, 1=Revoked, 2=Unknown); or -1 for no enforcement.")
	expectReason       = flag.Int("expect-reason", -1, "Expect response to have this numeric revocation reason (0=Unspecified, 1=KeyCompromise, etc); or -1 for no enforcement.")
)

// Config contains fields which control various behaviors of the
// checker's behavior.
type Config struct {
	method             string
	urlOverride        string
	hostOverride       string
	tooSoon            int
	ignoreExpiredCerts bool
	expectStatus       int
	expectReason       int
	output             io.Writer
}

// DefaultConfig is a Config populated with the same defaults as if no
// command-line had been provided, so all retain their default value.
var DefaultConfig = Config{
	method:             *method,
	urlOverride:        *urlOverride,
	hostOverride:       *hostOverride,
	tooSoon:            *tooSoon,
	ignoreExpiredCerts: *ignoreExpiredCerts,
	expectStatus:       *expectStatus,
	expectReason:       *expectReason,
	output:             os.Stdout,
}

var parseFlagsOnce sync.Once

// ConfigFromFlags returns a Config whose values are populated from
// any command line flags passed by the user, or default values if not passed.
func ConfigFromFlags() Config {
	parseFlagsOnce.Do(func() {
		flag.Parse()
	})
	return Config{
		method:             *method,
		urlOverride:        *urlOverride,
		hostOverride:       *hostOverride,
		tooSoon:            *tooSoon,
		ignoreExpiredCerts: *ignoreExpiredCerts,
		expectStatus:       *expectStatus,
		expectReason:       *expectReason,
	}
}

// WithExpectStatus returns a new Config with the given expectStatus,
// and all other fields the same as the receiver.
func (template Config) WithExpectStatus(status int) Config {
	ret := template
	ret.expectStatus = status
	return ret
}

// WithOutput returns a new Config with the given output,
// and all other fields the same as the receiver.
func (template Config) WithOutput(w io.Writer) Config {
	ret := template
	ret.output = w
	return ret
}

func getIssuer(cert *sm2.Certificate) (*sm2.Certificate, error) {
	if cert == nil {
		return nil, fmt.Errorf("nil certificate")
	}
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("No AIA information available, can't get issuer")
	}
	issuerURL := cert.IssuingCertificateURL[0]
	resp, err := http.Get(issuerURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var issuer *sm2.Certificate
	contentType := resp.Header.Get("Content-Type")
	if contentType == "application/x-pkcs7-mime" || contentType == "application/pkcs7-mime" {
		issuer, err = parseCMS(body)
	} else {
		issuer, err = parse(body)
	}
	if err != nil {
		return nil, fmt.Errorf("from %s: %s", issuerURL, err)
	}
	return issuer, nil
}

func parse(body []byte) (*sm2.Certificate, error) {
	block, _ := pem.Decode(body)
	var der []byte
	if block == nil {
		der = body
	} else {
		der = block.Bytes
	}
	cert, err := sm2.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// parseCMS parses certificates from CMS messages of type SignedData.
func parseCMS(body []byte) (*sm2.Certificate, error) {
	type signedData struct {
		Version          int
		Digests          asn1.RawValue
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue
	}
	type cms struct {
		ContentType asn1.ObjectIdentifier
		SignedData  signedData `asn1:"explicit,tag:0"`
	}
	var msg cms
	_, err := asn1.Unmarshal(body, &msg)
	if err != nil {
		return nil, fmt.Errorf("parsing CMS: %s", err)
	}
	cert, err := sm2.ParseCertificate(msg.SignedData.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CMS: %s", err)
	}
	return cert, nil
}

// Req makes an OCSP request using the given config for the PEM certificate in
// fileName, and returns the response.
func Req(fileName string, config Config) (*Response, error) {
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return ReqDER(contents, config)
}

// ReqDER makes an OCSP request using the given config for the given DER-encoded
// certificate, and returns the response.
func ReqDER(der []byte, config Config) (*Response, error) {
	cert, err := parse(der)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %s", err)
	}
	if time.Now().After(cert.NotAfter) {
		if config.ignoreExpiredCerts {
			return nil, nil
		} else {
			return nil, fmt.Errorf("certificate expired %s ago: %s",
				time.Since(cert.NotAfter), cert.NotAfter)
		}
	}

	issuer, err := getIssuer(cert)
	if err != nil {
		return nil, fmt.Errorf("getting issuer: %s", err)
	}


	//ocsp.response

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, err
	}
	h := sm2.SM3.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	prereq := &ocsp.Request{
		HashAlgorithm:  crypto.Hash(sm2.SM3),
		IssuerNameHash: issuerNameHash,
		IssuerKeyHash:  issuerKeyHash,
		SerialNumber:   cert.SerialNumber,
	}
	req ,err2 := prereq.Marshal()
	if err2 != nil {
		return nil,fmt.Errorf("[zzy-debug ocsp helper 222]creating OCSP request err : %q",err2)
	}
	//
	//req, err := ocsp.CreateRequest(cert, issuer, nil)
	//if err != nil {
	//	return nil, fmt.Errorf("creating OCSP request: %s", err)
	//}

	ocspURL, err := getOCSPURL(cert, config.urlOverride)
	if err != nil {
		return nil, err
	}

	httpResp, err := sendHTTPRequest(req, ocspURL, config.method, config.hostOverride, config.output)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(config.output, "HTTP %d\n", httpResp.StatusCode)
	for k, v := range httpResp.Header {
		for _, vv := range v {
			fmt.Fprintf(config.output, "%s: %s\n", k, vv)
		}
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("[zzy-debug ocsp helper 246]http status code %d", httpResp.StatusCode)
	}
	respBytes, err := ioutil.ReadAll(httpResp.Body)
	defer httpResp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(respBytes) == 0 {
		return nil, fmt.Errorf("[zzy-debug ocsp helper 254]empty response body")
	}
	return parseAndPrint(respBytes, cert, issuer, config)
}

func sendHTTPRequest(
	req []byte,
	ocspURL *url.URL,
	method string,
	host string,
	output io.Writer,
) (*http.Response, error) {
	encodedReq := base64.StdEncoding.EncodeToString(req)
	var httpRequest *http.Request
	var err error
	if method == "GET" {
		ocspURL.Path = encodedReq
		fmt.Fprintf(output, "Fetching %s\n", ocspURL.String())
		httpRequest, err = http.NewRequest("GET", ocspURL.String(), http.NoBody)
	} else if method == "POST" {
		fmt.Fprintf(output, "POSTing request, reproduce with: curl -i --data-binary @- %s < <(base64 -d <<<%s)\n",
			ocspURL, encodedReq)
		httpRequest, err = http.NewRequest("POST", ocspURL.String(), bytes.NewBuffer(req))
	} else {
		return nil, fmt.Errorf("invalid method %s, expected GET or POST", method)
	}
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	if host != "" {
		httpRequest.Host = host
	}
	client := http.Client{
		Timeout: 5 * time.Second,
	}

	return client.Do(httpRequest)
}

func getOCSPURL(cert *sm2.Certificate, urlOverride string) (*url.URL, error) {
	var ocspServer string
	if urlOverride != "" {
		ocspServer = urlOverride
	} else if len(cert.OCSPServer) > 0 {
		ocspServer = cert.OCSPServer[0]
	} else {
		return nil, fmt.Errorf("no ocsp servers in cert")
	}
	ocspURL, err := url.Parse(ocspServer)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %s", err)
	}
	return ocspURL, nil
}

// checkSignerTimes checks that the OCSP response is within the
// validity window of whichever certificate signed it, and that that
// certificate is currently valid.
func checkSignerTimes(resp *Response, issuer *sm2.Certificate, output io.Writer) error {
	var ocspSigner = issuer
	if delegatedSigner := resp.Certificate; delegatedSigner != nil {
		ocspSigner = delegatedSigner

		fmt.Fprintf(output, "Using delegated OCSP signer from response: %s\n",
			base64.StdEncoding.EncodeToString(ocspSigner.Raw))
	}

	if resp.NextUpdate.After(ocspSigner.NotAfter) {
		return fmt.Errorf("OCSP response is valid longer than OCSP signer (%s): %s is after %s",
			ocspSigner.Subject, resp.NextUpdate, ocspSigner.NotAfter)
	}
	if resp.ThisUpdate.Before(ocspSigner.NotBefore) {
		return fmt.Errorf("OCSP response's validity begins before the OCSP signer's (%s): %s is before %s",
			ocspSigner.Subject, resp.ThisUpdate, ocspSigner.NotBefore)
	}

	if time.Now().After(ocspSigner.NotAfter) {
		return fmt.Errorf("OCSP signer (%s) expired at %s", ocspSigner.Subject, ocspSigner.NotAfter)
	}
	if time.Now().Before(ocspSigner.NotBefore) {
		return fmt.Errorf("OCSP signer (%s) not valid until %s", ocspSigner.Subject, ocspSigner.NotBefore)
	}
	return nil
}

func parseAndPrint(respBytes []byte, cert, issuer *sm2.Certificate, config Config) (*Response, error) {
	fmt.Fprintf(config.output, "\nDecoding body: %s\n", base64.StdEncoding.EncodeToString(respBytes))
	resp, err := ParseResponseForCert(respBytes, cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing response: %s", err)
	}

	var errs []error
	if config.expectStatus != -1 && resp.Status != config.expectStatus {
		errs = append(errs, fmt.Errorf("wrong CertStatus %d, expected %d", resp.Status, config.expectStatus))
	}
	if config.expectReason != -1 && resp.RevocationReason != config.expectReason {
		errs = append(errs, fmt.Errorf("wrong RevocationReason %d, expected %d", resp.RevocationReason, config.expectReason))
	}
	timeTilExpiry := time.Until(resp.NextUpdate)
	tooSoonDuration := time.Duration(config.tooSoon) * time.Hour
	if timeTilExpiry < tooSoonDuration {
		errs = append(errs, fmt.Errorf("NextUpdate is too soon: %s", timeTilExpiry))
	}

	err = checkSignerTimes(resp, issuer, config.output)
	if err != nil {
		errs = append(errs, fmt.Errorf("checking signature on delegated signer: %s", err))
	}

	pr := func(s string, v ...interface{}) {
		fmt.Fprintf(config.output, s, v)
	}

	pr("\n")
	pr("Response:\n")
	pr("  CertStatus %d\n", resp.Status)
	pr("  SerialNumber %036x\n", resp.SerialNumber)
	pr("  ProducedAt %s\n", resp.ProducedAt)
	pr("  ThisUpdate %s\n", resp.ThisUpdate)
	pr("  NextUpdate %s\n", resp.NextUpdate)
	pr("  RevokedAt %s\n", resp.RevokedAt)
	pr("  RevocationReason %d\n", resp.RevocationReason)
	pr("  SignatureAlgorithm %s\n", resp.SignatureAlgorithm)
	pr("  Extensions %#v\n", resp.Extensions)
	if resp.Certificate == nil {
		pr("  Certificate: nil\n")
	} else {
		pr("  Certificate:\n")
		pr("    Subject: %s\n", resp.Certificate.Subject)
		pr("    Issuer: %s\n", resp.Certificate.Issuer)
		pr("    NotBefore: %s\n", resp.Certificate.NotBefore)
		pr("    NotAfter: %s\n", resp.Certificate.NotAfter)
	}

	if len(errs) > 0 {
		fmt.Print("Errors:\n")
		err := errs[0]
		fmt.Printf("  %v\n", err.Error())
		for _, e := range errs[1:] {
			err = fmt.Errorf("%w; %v", err, e)
			fmt.Printf("  %v\n", e.Error())
		}
		return nil, err
	}
	fmt.Print("No errors found.\n")
	return resp, nil
}

type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}


type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []singleResponse
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

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}
type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}
var idPKIXOCSPBasic = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 7, 48, 1, 1})


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

// TODO(agl): this is taken from crypto/x509 and so should probably be exported
// from crypto/x509 or crypto/x509/pkix.
func getSignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) sm2.SignatureAlgorithm {
	for _, details := range signatureAlgorithmDetails {
		if oid.Equal(details.oid) {
			return details.algo
		}
	}
	return sm2.UnknownSignatureAlgorithm
}

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

var hashOIDs = map[sm2.Hash]asn1.ObjectIdentifier{
	sm2.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	sm2.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	sm2.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	sm2.SM3	: asn1.ObjectIdentifier([]int{1, 2, 156, 10197, 1, 401, 1}),
	sm2.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}

func ParseResponseForCert(bytes []byte, cert, issuer *sm2.Certificate) (*Response, error) {
	var resp responseASN1
	rest, err := asn1.Unmarshal(bytes, &resp)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, ocsp.ParseError("trailing data in OCSP response")
	}

	if status := ocsp.ResponseStatus(resp.Status); status != ocsp.Success {
		return nil, ocsp.ResponseError{status}
	}

	if !resp.Response.ResponseType.Equal(idPKIXOCSPBasic) {
		return nil, ocsp.ParseError("bad OCSP response type")
	}

	var basicResp basicResponse
	rest, err = asn1.Unmarshal(resp.Response.Response, &basicResp)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, ocsp.ParseError("trailing data in OCSP response")
	}

	if n := len(basicResp.TBSResponseData.Responses); n == 0 || cert == nil && n > 1 {
		return nil, ocsp.ParseError("OCSP response contains bad number of responses")
	}

	var singleResp singleResponse
	if cert == nil {
		singleResp = basicResp.TBSResponseData.Responses[0]
	} else {
		match := false
		for _, resp := range basicResp.TBSResponseData.Responses {
			if cert.SerialNumber.Cmp(resp.CertID.SerialNumber) == 0 {
				singleResp = resp
				match = true
				break
			}
		}
		if !match {
			return nil, ocsp.ParseError("no response matching the supplied certificate")
		}
	}

	ret := &Response{
		TBSResponseData:    basicResp.TBSResponseData.Raw,
		Signature:          basicResp.Signature.RightAlign(),
		SignatureAlgorithm: getSignatureAlgorithmFromOID(basicResp.SignatureAlgorithm.Algorithm),
		Extensions:         singleResp.SingleExtensions,
		SerialNumber:       singleResp.CertID.SerialNumber,
		ProducedAt:         basicResp.TBSResponseData.ProducedAt,
		ThisUpdate:         singleResp.ThisUpdate,
		NextUpdate:         singleResp.NextUpdate,
	}

	// Handle the ResponderID CHOICE tag. ResponderID can be flattened into
	// TBSResponseData once https://go-review.googlesource.com/34503 has been
	// released.
	rawResponderID := basicResp.TBSResponseData.RawResponderID
	switch rawResponderID.Tag {
	case 1: // Name
		var rdn pkix.RDNSequence
		if rest, err := asn1.Unmarshal(rawResponderID.Bytes, &rdn); err != nil || len(rest) != 0 {
			return nil, ocsp.ParseError("invalid responder name")
		}
		ret.RawResponderName = rawResponderID.Bytes
	case 2: // KeyHash
		if rest, err := asn1.Unmarshal(rawResponderID.Bytes, &ret.ResponderKeyHash); err != nil || len(rest) != 0 {
			return nil, ocsp.ParseError("invalid responder key hash")
		}
	default:
		return nil, ocsp.ParseError("invalid responder id tag")
	}

	if len(basicResp.Certificates) > 0 {
		// Responders should only send a single certificate (if they
		// send any) that connects the responder's certificate to the
		// original issuer. We accept responses with multiple
		// certificates due to a number responders sending them[1], but
		// ignore all but the first.
		//
		// [1] https://github.com/golang/go/issues/21527
		ret.Certificate, err = sm2.ParseCertificate(basicResp.Certificates[0].FullBytes)
		if err != nil {
			return nil, err
		}
		//if err := ret.Certificate.CheckSignature(ret.SignatureAlgorithm, ret.TBSResponseData, ret.Signature); err == nil {
		////if err := ret.CheckSignatureFrom(ret.Certificate); err != nil {
		//	return nil, ocsp.ParseError("bad signature on embedded certificate: " + err.Error())
		//}

		//if issuer != nil {
		//	if err := issuer.CheckSignature(ret.Certificate.SignatureAlgorithm, ret.Certificate.RawTBSCertificate, ret.Certificate.Signature); err != nil {
		//		return nil, ocsp.ParseError("bad OCSP signature: " + err.Error())
		//	}
		//}
	}
	//else if issuer != nil {
	//	if err := ret.Certificate.CheckSignatureFrom(issuer); err != nil {
	//		return nil, ocsp.ParseError("bad OCSP signature: " + err.Error())
	//	}
	//}

	for _, ext := range singleResp.SingleExtensions {
		if ext.Critical {
			return nil, ocsp.ParseError("unsupported critical extension")
		}
	}

	for h, oid := range hashOIDs {
		if singleResp.CertID.HashAlgorithm.Algorithm.Equal(oid) {
			ret.IssuerHash = h
			break
		}
	}
	if ret.IssuerHash == 0 {
		return nil, ocsp.ParseError("unsupported issuer hash algorithm")
	}

	switch {
	case bool(singleResp.Good):
		ret.Status = ocsp.Good
	case bool(singleResp.Unknown):
		ret.Status = ocsp.Unknown
	default:
		ret.Status = ocsp.Revoked
		ret.RevokedAt = singleResp.Revoked.RevocationTime
		ret.RevocationReason = int(singleResp.Revoked.Reason)
	}

	return ret, nil
}

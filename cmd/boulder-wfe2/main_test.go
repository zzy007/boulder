package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestLoadCertificateChains(t *testing.T) {
	// Read some cert bytes to use for expected chain content
	certBytesA, err := ioutil.ReadFile("../../test/test-ca.pem")
	test.AssertNotError(t, err, "Error reading../../test/test-ca.pem")
	certBytesB, err := ioutil.ReadFile("../../test/test-ca2.pem")
	test.AssertNotError(t, err, "Error reading../../test/test-ca2.pem")

	// Make a .pem file with invalid contents
	invalidPEMFile, _ := ioutil.TempFile("", "invalid.pem")
	err = ioutil.WriteFile(invalidPEMFile.Name(), []byte(""), 0640)
	test.AssertNotError(t, err, "Error writing invalid PEM tmp file")

	// Make a .pem file with a valid cert but also some leftover bytes
	leftoverPEMFile, _ := ioutil.TempFile("", "leftovers.pem")
	leftovers := "vegan curry, cold rice, soy milk"
	leftoverBytes := append(certBytesA, []byte(leftovers)...)
	err = ioutil.WriteFile(leftoverPEMFile.Name(), leftoverBytes, 0640)
	test.AssertNotError(t, err, "Error writing leftover PEM tmp file")

	// Make a .pem file that is test-ca2.pem but with Windows/DOS CRLF line
	// endings
	crlfPEM, _ := ioutil.TempFile("", "crlf.pem")
	crlfPEMBytes := []byte(strings.Replace(string(certBytesB), "\n", "\r\n", -1))
	err = ioutil.WriteFile(crlfPEM.Name(), crlfPEMBytes, 0640)
	test.AssertNotError(t, err, "ioutil.WriteFile failed")

	// Make a .pem file that is test-ca.pem but with no trailing newline
	abruptPEM, _ := ioutil.TempFile("", "abrupt.pem")
	abruptPEMBytes := certBytesA[:len(certBytesA)-1]
	err = ioutil.WriteFile(abruptPEM.Name(), abruptPEMBytes, 0640)
	test.AssertNotError(t, err, "ioutil.WriteFile failed")

	testCases := []struct {
		Name            string
		Input           map[string][]string
		ExpectedMap     map[string][]byte
		ExpectedError   error
		AllowEmptyChain bool
	}{
		{
			Name:  "No input",
			Input: nil,
		},
		{
			Name: "AIA Issuer without chain files",
			Input: map[string][]string{
				"http://break.the.chain.com": {},
			},
			ExpectedError: fmt.Errorf(
				"CertificateChain entry for AIA issuer url \"http://break.the.chain.com\" " +
					"has no chain file names configured"),
		},
		{
			Name: "Missing chain file",
			Input: map[string][]string{
				"http://where.is.my.mind": {"/tmp/does.not.exist.pem"},
			},
			ExpectedError: fmt.Errorf("CertificateChain entry for AIA issuer url \"http://where.is.my.mind\" " +
				"has an invalid chain file: \"/tmp/does.not.exist.pem\" - error reading " +
				"contents: open /tmp/does.not.exist.pem: no such file or directory"),
		},
		{
			Name: "PEM chain file with Windows CRLF line endings",
			Input: map[string][]string{
				"http://windows.sad.zone": {crlfPEM.Name()},
			},
			ExpectedError: fmt.Errorf("CertificateChain entry for AIA issuer url \"http://windows.sad.zone\" "+
				"has an invalid chain file: %q - contents had CRLF line endings", crlfPEM.Name()),
		},
		{
			Name: "Invalid PEM chain file",
			Input: map[string][]string{
				"http://ok.go": {invalidPEMFile.Name()},
			},
			ExpectedError: fmt.Errorf(
				"CertificateChain entry for AIA issuer url \"http://ok.go\" has an "+
					"invalid chain file: %q - contents did not decode as PEM",
				invalidPEMFile.Name()),
		},
		{
			Name: "PEM chain file that isn't a cert",
			Input: map[string][]string{
				"http://not-a-cert.com": {"../../test/test-root.key"},
			},
			ExpectedError: fmt.Errorf(
				"CertificateChain entry for AIA issuer url \"http://not-a-cert.com\" has " +
					"an invalid chain file: \"../../test/test-root.key\" - PEM block type " +
					"incorrect, found \"PRIVATE KEY\", expected \"CERTIFICATE\""),
		},
		{
			Name: "PEM chain file with leftover bytes",
			Input: map[string][]string{
				"http://tasty.leftovers.com": {leftoverPEMFile.Name()},
			},
			ExpectedError: fmt.Errorf(
				"CertificateChain entry for AIA issuer url \"http://tasty.leftovers.com\" "+
					"has an invalid chain file: %q - PEM contents had unused remainder input "+
					"(%d bytes)",
				leftoverPEMFile.Name(),
				len([]byte(leftovers)),
			),
		},
		{
			Name: "One PEM file chain",
			Input: map[string][]string{
				"http://single-cert-chain.com": {"../../test/test-ca.pem"},
			},
			ExpectedMap: map[string][]byte{
				"http://single-cert-chain.com": []byte(fmt.Sprintf("\n%s", string(certBytesA))),
			},
		},
		{
			Name: "Two PEM file chain",
			Input: map[string][]string{
				"http://two-cert-chain.com": {"../../test/test-ca.pem", "../../test/test-ca2.pem"},
			},
			ExpectedMap: map[string][]byte{
				"http://two-cert-chain.com": []byte(fmt.Sprintf("\n%s\n%s", string(certBytesA), string(certBytesB))),
			},
		},
		{
			Name: "One PEM file chain, no trailing newline",
			Input: map[string][]string{
				"http://single-cert-chain.nonewline.com": {abruptPEM.Name()},
			},
			ExpectedMap: map[string][]byte{
				// NOTE(@cpu): There should be a trailing \n added by the WFE that we
				// expect in the format specifier below.
				"http://single-cert-chain.nonewline.com": []byte(fmt.Sprintf("\n%s\n", string(abruptPEMBytes))),
			},
		},
		{
			Name:            "Two PEM file chain, don't require at least one chain",
			AllowEmptyChain: true,
			Input: map[string][]string{
				"http://two-cert-chain.com": {"../../test/test-ca.pem", "../../test/test-ca2.pem"},
			},
			ExpectedMap: map[string][]byte{
				"http://two-cert-chain.com": []byte(fmt.Sprintf("\n%s\n%s", string(certBytesA), string(certBytesB))),
			},
		},
		{
			Name:            "Empty chain, don't require at least one chain",
			AllowEmptyChain: true,
			Input: map[string][]string{
				"http://two-cert-chain.com": {},
			},
			ExpectedMap: map[string][]byte{},
		},
		{
			Name: "Empty chain",
			Input: map[string][]string{
				"http://two-cert-chain.com": {},
			},
			ExpectedError: fmt.Errorf(
				"CertificateChain entry for AIA issuer url %q has no chain "+
					"file names configured",
				"http://two-cert-chain.com"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			resultMap, issuers, err := loadCertificateChains(tc.Input, !tc.AllowEmptyChain)
			if tc.ExpectedError == nil && err != nil {
				t.Errorf("Expected nil error, got %#v\n", err)
			} else if tc.ExpectedError != nil && err == nil {
				t.Errorf("Expected non-nil error, got nil err")
			} else if tc.ExpectedError != nil {
				test.AssertEquals(t, err.Error(), tc.ExpectedError.Error())
			}
			test.AssertEquals(t, len(resultMap), len(tc.ExpectedMap))
			test.AssertEquals(t, len(issuers), len(tc.ExpectedMap))
			for url, chain := range resultMap {
				test.Assert(t, bytes.Equal(chain, tc.ExpectedMap[url]), "Chain bytes did not match expected")
			}
		})
	}
}

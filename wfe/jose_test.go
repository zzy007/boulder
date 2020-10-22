package wfe

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"

	"gopkg.in/square/go-jose.v2"
)

func TestRejectsNone(t *testing.T) {
	wfe, _ := setupWFE(t)
	_, _, _, prob := wfe.verifyPOST(ctx, newRequestEvent(), makePostRequest(`
		{
			"header": {
				"alg": "none",
				"jwk": {
					"kty": "RSA",
					"n": "vrjT",
					"e": "AQAB"
				}
			},
			"payload": "aGkK",
			"signature": ""
		}
	`), true, "foo")
	if prob == nil {
		t.Fatalf("verifyPOST did not reject JWS with alg: 'none'")
	}
	if prob.Detail != "JWS signature header contains unsupported algorithm \"none\", expected one of RS256, ES256, ES384 or ES512" {
		t.Fatalf("verifyPOST rejected JWS with alg: 'none', but for wrong reason: %#v", prob)
	}
}

func TestRejectsHS256(t *testing.T) {
	wfe, _ := setupWFE(t)
	_, _, _, prob := wfe.verifyPOST(ctx, newRequestEvent(), makePostRequest(`
		{
			"header": {
				"alg": "HS256",
				"jwk": {
					"kty": "RSA",
					"n": "vrjT",
					"e": "AQAB"
				}
			},
			"payload": "aGkK",
			"signature": ""
		}
	`), true, "foo")
	if prob == nil {
		t.Fatalf("verifyPOST did not reject JWS with alg: 'HS256'")
	}
	expected := "JWS signature header contains unsupported algorithm \"HS256\", expected one of RS256, ES256, ES384 or ES512"
	if prob.Detail != expected {
		t.Fatalf("verifyPOST rejected JWS with alg: 'none', but for wrong reason: got %q, wanted %q", prob, expected)
	}
}

func TestCheckAlgorithm(t *testing.T) {
	testCases := []struct {
		key          jose.JSONWebKey
		jws          jose.JSONWebSignature
		expectedErr  string
		expectedStat string
	}{
		{
			jose.JSONWebKey{},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "HS256",
						},
					},
				},
			},
			"JWS signature header contains unsupported algorithm \"HS256\", expected one of RS256, ES256, ES384 or ES512",
			invalidJWSAlgorithm,
		},
		{
			jose.JSONWebKey{
				Key: &dsa.PublicKey{},
			},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "ES512",
						},
					},
				},
			},
			"JWK contains unsupported key type (expected RSA, or ECDSA P-256, P-384, or P-521",
			noAlgorithmForKey,
		},
		{
			jose.JSONWebKey{
				Algorithm: "RS256",
				Key:       &rsa.PublicKey{},
			},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "ES512",
						},
					},
				},
			},
			"JWS signature header algorithm \"ES512\" does not match expected algorithm \"RS256\" for JWK",
			invalidJWSAlgorithm,
		},
		{
			jose.JSONWebKey{
				Algorithm: "HS256",
				Key:       &rsa.PublicKey{},
			},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "RS256",
						},
					},
				},
			},
			"JWK key header algorithm \"HS256\" does not match expected algorithm \"RS256\" for JWK",
			invalidAlgorithmOnKey,
		},
	}
	for i, tc := range testCases {
		stat, err := checkAlgorithm(&tc.key, &tc.jws)
		if tc.expectedErr != "" && err.Error() != tc.expectedErr {
			t.Errorf("TestCheckAlgorithm %d: Expected '%s', got '%s'", i, tc.expectedErr, err)
		}
		if tc.expectedStat != "" && stat != tc.expectedStat {
			t.Errorf("TestCheckAlgorithm %d: Expected stat '%s', got '%s'", i, tc.expectedStat, stat)
		}
	}
}

func TestCheckAlgorithmSuccess(t *testing.T) {
	_, err := checkAlgorithm(&jose.JSONWebKey{
		Algorithm: "RS256",
		Key:       &rsa.PublicKey{},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "RS256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("RS256 key: Expected nil error, got '%s'", err)
	}
	_, err = checkAlgorithm(&jose.JSONWebKey{
		Key: &rsa.PublicKey{},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "RS256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("RS256 key: Expected nil error, got '%s'", err)
	}

	_, err = checkAlgorithm(&jose.JSONWebKey{
		Algorithm: "ES256",
		Key: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "ES256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("ES256 key: Expected nil error, got '%s'", err)
	}

	_, err = checkAlgorithm(&jose.JSONWebKey{
		Key: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "ES256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("ES256 key: Expected nil error, got '%s'", err)
	}
}

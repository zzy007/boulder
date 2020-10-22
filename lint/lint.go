package lint

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"strings"

	zlintx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2"
	"github.com/zmap/zlint/v2/lint"
)

// Check accomplishes the entire process of linting: it generates a throwaway
// signing key, uses that to create a throwaway cert, and runs a default set
// of lints (everything except for the ETSI and EV lints) against it. This is
// the primary public interface of this package, but it can be inefficient;
// creating a new signer and a new lint registry are expensive operations which
// performance-sensitive clients may want to cache.
func Check(tbs, issuer *sm2.Certificate, subjectPubKey crypto.PublicKey, realSigner crypto.Signer, skipLints []string) error {
	lintSigner, err := MakeSigner(realSigner)
	if err != nil {
		return err
	}
	lintCert, err := MakeLintCert(tbs, issuer, subjectPubKey, lintSigner)
	if err != nil {
		return err
	}
	reg, err := MakeRegistry(skipLints)
	if err != nil {
		return err
	}
	return LintCert(lintCert, reg)
}

// MakeSigner creates a throwaway crypto.Signer with the same key algorithm
// as the given Signer. This is useful if you intend to lint many certs are
// okay using the same throwaway key to sign all of them.
func MakeSigner(realSigner crypto.Signer) (crypto.Signer, error) {
	var lintSigner crypto.Signer
	var err error
	switch k := realSigner.Public().(type) {
	//case *rsa.PublicKey:
	//	lintSigner, err = rsa.GenerateKey(rand.Reader, k.Size()*8)
	//	if err != nil {
	//		return nil, fmt.Errorf("failed to create RSA lint signer: %w", err)
	//	}
	case *ecdsa.PublicKey:
		//lintSigner, err = ecdsa.GenerateKey(k.Curve, rand.Reader)
		lintSigner, err = sm2.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to create sm2 lint signer: %w", err)
		}
	case *sm2.PublicKey:
		//lintSigner, err = ecdsa.GenerateKey(k.Curve, rand.Reader)
		lintSigner, err = sm2.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to create sm2 lint signer: %w", err)
		}
	default:
		return nil, fmt.Errorf("[zzy-debug lint 63] unsupported lint signer type: %T", k)
	}
	return lintSigner, nil
}

// MakeRegistry creates a zlint Registry of lints to run, filtering out the
// EV- and ETSI-specific lints, as well as any others specified.
func MakeRegistry(skipLints []string) (lint.Registry, error) {
	reg, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
		ExcludeNames: skipLints,
		ExcludeSources: []lint.LintSource{
			lint.CABFEVGuidelines,
			lint.EtsiEsi,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create lint registry: %w", err)
	}
	return reg, nil
}

// MakeLintCert creates a throwaway x509.Certificate which can be linted.
// Only use the result from MakeSigner as the final argument.
func MakeLintCert(tbs, issuer *sm2.Certificate, subjectPubKey crypto.PublicKey, lintSigner crypto.Signer) (*zlintx509.Certificate, error) {
	lintCertBytes, err := sm2.CreateCertificate(rand.Reader, tbs, issuer, subjectPubKey, lintSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create lint certificate: %w", err)
	}
	lintCert, err := zlintx509.ParseCertificate(lintCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse lint certificate: %w", err)
	}
	return lintCert, nil
}

// LintCert runs the given set of lints across the given cert and returns
// an error containing the names of all failed lints, or nil.
func LintCert(lintCert *zlintx509.Certificate, lints lint.Registry) error {
	lintRes := zlint.LintCertificateEx(lintCert, lints)
	if lintRes.NoticesPresent || lintRes.WarningsPresent || lintRes.ErrorsPresent || lintRes.FatalsPresent {
		var failedLints []string
		for lintName, result := range lintRes.Results {
			if result.Status > lint.Pass {
				failedLints = append(failedLints, lintName)
			}
		}
		return fmt.Errorf("failed lints: %s", strings.Join(failedLints, ", "))
	}
	return nil
}

type Linter struct {
	signer   crypto.Signer
	registry lint.Registry
}

func NewLinter(realSigner crypto.Signer, skipLints []string) (*Linter, error) {
	signer, err := MakeSigner(realSigner)
	if err != nil {
		return nil, err
	}
	reg, err := MakeRegistry(skipLints)
	if err != nil {
		return nil, err
	}
	return &Linter{signer, reg}, nil
}

func (l Linter) LintTBS(tbs, issuer *sm2.Certificate, subjectPubKey crypto.PublicKey) error {
	cert, err := MakeLintCert(tbs, issuer, subjectPubKey, l.signer)
	if err != nil {
		return err
	}
	return LintCert(cert, l.registry)
}

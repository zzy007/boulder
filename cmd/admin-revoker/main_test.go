package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

type mockCA struct {
	mocks.MockCA
}

func (ca *mockCA) GenerateOCSP(ctx context.Context, req *capb.GenerateOCSPRequest) (*capb.OCSPResponse, error) {
	return &capb.OCSPResponse{}, nil
}

func TestRevokeBatch(t *testing.T) {
	log := blog.UseMock()
	fc := clock.NewFake()
	// Set to some non-zero time.
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	dbMap, err := sa.NewDbMap(vars.DBConnSA, 0)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NoopRegisterer, 1)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	defer test.ResetSATestDatabase(t)
	reg := satest.CreateWorkingRegistration(t, ssa)

	ra := ra.NewRegistrationAuthorityImpl(fc,
		log,
		metrics.NoopRegisterer,
		1, goodkey.KeyPolicy{}, 100, true, 300*24*time.Hour, 7*24*time.Hour, nil, nil, 0, nil, nil, &x509.Certificate{})
	ra.SA = ssa
	ra.CA = &mockCA{}

	serialFile, err := ioutil.TempFile("", "serials")
	test.AssertNotError(t, err, "failed to open temp file")
	defer os.Remove(serialFile.Name())

	serials := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	k, err := rsa.GenerateKey(rand.Reader, 512)
	test.AssertNotError(t, err, "failed to generate test key")
	for _, serial := range serials {
		template := &x509.Certificate{
			SerialNumber: serial,
			DNSNames:     []string{"asd"},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
		test.AssertNotError(t, err, "failed to generate test cert")
		_, err = ssa.AddPrecertificate(context.Background(), &sapb.AddCertificateRequest{
			Der:      der,
			RegID:    reg.ID,
			Issued:   time.Now().UnixNano(),
			IssuerID: 1,
		})
		test.AssertNotError(t, err, "failed to add test cert")
		now := time.Now()
		_, err = ssa.AddCertificate(context.Background(), der, reg.ID, nil, &now)
		test.AssertNotError(t, err, "failed to add test cert")
		_, err = serialFile.WriteString(fmt.Sprintf("%s\n", core.SerialToString(serial)))
		test.AssertNotError(t, err, "failed to write serial to temp file")
	}

	err = revokeBatch(ra, log, dbMap, serialFile.Name(), 0, 2)
	test.AssertNotError(t, err, "revokeBatch failed")

	for _, serial := range serials {
		status, err := ssa.GetCertificateStatus(context.Background(), core.SerialToString(serial))
		test.AssertNotError(t, err, "failed to retrieve certificate status")
		test.AssertEquals(t, status.Status, core.OCSPStatusRevoked)
	}
}

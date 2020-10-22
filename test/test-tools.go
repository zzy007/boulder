package test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

// Assert a boolean
func Assert(t *testing.T, result bool, message string) {
	t.Helper()
	if !result {
		t.Fatal(message)
	}
}

// AssertNotNil checks an object to be non-nil
func AssertNotNil(t *testing.T, obj interface{}, message string) {
	t.Helper()
	if obj == nil {
		t.Fatal(message)
	}
}

// AssertNotError checks that err is nil
func AssertNotError(t *testing.T, err error, message string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", message, err)
	}
}

// AssertError checks that err is non-nil
func AssertError(t *testing.T, err error, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error but received none", message)
	}
}

// AssertEquals uses the equality operator (==) to measure one and two
func AssertEquals(t *testing.T, one interface{}, two interface{}) {
	t.Helper()
	if reflect.TypeOf(one) != reflect.TypeOf(two) {
		t.Fatalf("cannot test equality of different types: %T != %T", one, two)
	}
	if one != two {
		t.Fatalf("%#v != %#v", one, two)
	}
}

// AssertDeepEquals uses the reflect.DeepEqual method to measure one and two
func AssertDeepEquals(t *testing.T, one interface{}, two interface{}) {
	t.Helper()
	if !reflect.DeepEqual(one, two) {
		t.Fatalf("[%+v] !(deep)= [%+v]", one, two)
	}
}

// AssertMarshaledEquals marshals one and two to JSON, and then uses
// the equality operator to measure them
func AssertMarshaledEquals(t *testing.T, one interface{}, two interface{}) {
	t.Helper()
	oneJSON, err := json.Marshal(one)
	AssertNotError(t, err, "Could not marshal 1st argument")
	twoJSON, err := json.Marshal(two)
	AssertNotError(t, err, "Could not marshal 2nd argument")

	if !bytes.Equal(oneJSON, twoJSON) {
		t.Fatalf("[%s] !(json)= [%s]", oneJSON, twoJSON)
	}
}

// AssertUnmarshaledEquals unmarshals two JSON strings (got and expected) to
// a map[string]interface{} and then uses reflect.DeepEqual to check they are
// the same
func AssertUnmarshaledEquals(t *testing.T, got, expected string) {
	t.Helper()
	var gotMap, expectedMap map[string]interface{}
	err := json.Unmarshal([]byte(got), &gotMap)
	AssertNotError(t, err, "Could not unmarshal 'got'")
	err = json.Unmarshal([]byte(expected), &expectedMap)
	AssertNotError(t, err, "Could not unmarshal 'expected'")
	if len(gotMap) != len(expectedMap) {
		t.Errorf("Expected had %d keys, got had %d", len(gotMap), len(expectedMap))
	}
	for k, v := range expectedMap {
		if !reflect.DeepEqual(v, gotMap[k]) {
			t.Errorf("Field %q: Expected \"%v\", got \"%v\"", k, v, gotMap[k])
		}
	}
}

// AssertNotEquals uses the equality operator to measure that one and two
// are different
func AssertNotEquals(t *testing.T, one interface{}, two interface{}) {
	t.Helper()
	if one == two {
		t.Fatalf("%#v == %#v", one, two)
	}
}

// AssertByteEquals uses bytes.Equal to measure one and two for equality.
func AssertByteEquals(t *testing.T, one []byte, two []byte) {
	t.Helper()
	if !bytes.Equal(one, two) {
		t.Fatalf("Byte [%s] != [%s]",
			base64.StdEncoding.EncodeToString(one),
			base64.StdEncoding.EncodeToString(two))
	}
}

// AssertContains determines whether needle can be found in haystack
func AssertContains(t *testing.T, haystack string, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("String [%s] does not contain [%s]", haystack, needle)
	}
}

// AssertNotContains determines if needle is not found in haystack
func AssertNotContains(t *testing.T, haystack string, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Fatalf("String [%s] contains [%s]", haystack, needle)
	}
}

// CountCounterVec returns the count by label and value of a prometheus metric
func CountCounterVec(labelName string, value string, counterVec *prometheus.CounterVec) int {
	return CountCounter(counterVec.With(prometheus.Labels{labelName: value}))
}

// CountCounter returns the count by label and value of a prometheus metric
func CountCounter(counter prometheus.Counter) int {
	ch := make(chan prometheus.Metric, 10)
	counter.Collect(ch)
	var m prometheus.Metric
	select {
	case <-time.After(time.Second):
		panic("timed out collecting metrics")
	case m = <-ch:
	}
	var iom io_prometheus_client.Metric
	_ = m.Write(&iom)
	return int(iom.Counter.GetValue())
}

func CountHistogramSamples(obs prometheus.Observer) int {
	hist := obs.(prometheus.Histogram)
	ch := make(chan prometheus.Metric, 10)
	hist.Collect(ch)
	var m prometheus.Metric
	select {
	case <-time.After(time.Second):
		panic("timed out collecting metrics")
	case m = <-ch:
	}
	var iom io_prometheus_client.Metric
	_ = m.Write(&iom)
	return int(iom.Histogram.GetSampleCount())
}

// GaugeValueWithLabels returns the current value with the provided labels from the
// the GaugeVec argument, or an error if there was a problem collecting the value.
func GaugeValueWithLabels(vecGauge *prometheus.GaugeVec, labels prometheus.Labels) (int, error) {
	gauge, err := vecGauge.GetMetricWith(labels)
	if err != nil {
		return 0, err
	}

	ch := make(chan prometheus.Metric, 10)
	gauge.Collect(ch)
	var m prometheus.Metric
	select {
	case <-time.After(time.Second):
		return 0, fmt.Errorf("timed out collecting gauge metrics")
	case m = <-ch:
	}
	var iom io_prometheus_client.Metric
	_ = m.Write(&iom)

	return int(iom.Gauge.GetValue()), nil
}

// ThrowAwayCert is a small test helper function that creates a self-signed
// certificate for nameCount random example.com subdomains and returns the
// parsed certificate  and the random serial in string form or aborts the test.
// The certificate returned from this function is the bare minimum needed for
// most tests and isn't a robust example of a complete end entity certificate.
func ThrowAwayCert(t *testing.T, nameCount int) (string, *x509.Certificate) {
	var serialBytes [16]byte
	_, _ = rand.Read(serialBytes[:])
	sn := big.NewInt(0).SetBytes(serialBytes[:])

	return ThrowAwayCertWithSerial(t, nameCount, sn)
}

// ThrowAwayCertWithSerial is a small test helper function that creates a self-signed
// certificate for nameCount random example.com subdomains and returns the
// parsed certificate and the serial in string form or aborts the test.
// The certificate returned from this function is the bare minimum needed for
// most tests and isn't a robust example of a complete end entity certificate.
func ThrowAwayCertWithSerial(t *testing.T, nameCount int, sn *big.Int) (string, *x509.Certificate) {
	k, err := rsa.GenerateKey(rand.Reader, 512)
	AssertNotError(t, err, "rsa.GenerateKey failed")

	var names []string
	for i := 0; i < nameCount; i++ {
		var nameBytes [3]byte
		_, _ = rand.Read(nameBytes[:])
		names = append(names, fmt.Sprintf("%s.example.com", hex.EncodeToString(nameBytes[:])))
	}

	template := &x509.Certificate{
		SerialNumber:          sn,
		DNSNames:              names,
		IssuingCertificateURL: []string{"http://localhost:4000/acme/issuer-cert"},
	}
	testCertDER, err := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	AssertNotError(t, err, "x509.CreateCertificate failed")
	testCert, err := x509.ParseCertificate(testCertDER)
	AssertNotError(t, err, "failed to parse self-signed cert DER")
	return fmt.Sprintf("%036x", sn), testCert
}

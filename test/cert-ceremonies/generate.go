package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"text/template"

	"github.com/letsencrypt/boulder/cmd"
)

// createSlot initializes a SoftHSM slot and token. SoftHSM chooses the highest empty
// slot, initializes it, and then assigns it a new randomly chosen slot ID. Since we can't
// predict this ID we need to parse out the new ID so that we can use it in the ceremony
// configs.
func createSlot(label string) (string, error) {
	//
	//cmd := exec.Command("softhsm2-util", "--init-token", "--free", "--label", label, "--pin", "1234", "--so-pin", "5678")
	//
	//var out bytes.Buffer
	//var stderr bytes.Buffer
	//cmd.Stdout = &out
	//cmd.Stderr = &stderr
	//err1 := cmd.Run()
	//if err1 != nil {
	//	return "", fmt.Errorf(fmt.Sprint(err1) + ": " + stderr.String())
	//}
	output, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", label, "--pin", "1234", "--so-pin", "5678").CombinedOutput()
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`to slot (\d+)`)
	matches := re.FindSubmatch(output)
	if len(matches) != 2 {
		return "", errors.New("unexpected number of slot matches")
	}
	return string(matches[1]), nil
}

// genKey is used to run a key ceremony with a given config, replacing SlotID in
// the YAML with a specific slot ID.
func genKey(path string, inSlot string) error {
	// path : test/cert-ceremonies/root-ceremony-sm2.yaml
	tmpPath, err := rewriteConfig(path, map[string]string{"SlotID": inSlot})
	if err != nil {
		return err
	}
	//cmd := exec.Command("bin/ceremony", "-config", tmpPath)
	//
	//var out bytes.Buffer
	//var stderr bytes.Buffer
	//cmd.Stdout = &out
	//cmd.Stderr = &stderr
	//err1 := cmd.Run()
	//if err1 != nil {
	//	return  fmt.Errorf(fmt.Sprint(err1) + ": " + stderr.String())
	//}
	output, err := exec.Command("bin/ceremony", "-config", tmpPath).CombinedOutput()
	if err != nil {
		// err : err running ceremony for /tmp/ceremony-config945972704
		return fmt.Errorf("error running ceremony for %s: %s:\n%s", tmpPath, err, string(output))
	}
	return nil
}

// rewriteConfig creates a temporary config based on the template at path
// using the variables in rewrites.
func rewriteConfig(path string, rewrites map[string]string) (string, error) {
	tmplBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	tmp, err := ioutil.TempFile(os.TempDir(), "ceremony-config")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	tmpl, err := template.New("config").Parse(string(tmplBytes))
	if err != nil {
		return "", err
	}
	err = tmpl.Execute(tmp, rewrites)
	if err != nil {
		return "", err
	}
	return tmp.Name(), nil
}

// genCert is used to run ceremony when we don't actually care about,
// any of the output and only want to verify it exits cleanly
func genCert(path string) error {
	//return exec.Command("bin/ceremony", "-config", path).Run()
	//cmd := exec.Command("bin/ceremony", "-config", path)
	//
	//var out bytes.Buffer
	//var stderr bytes.Buffer
	//cmd.Stdout = &out
	//cmd.Stderr = &stderr
	//err1 := cmd.Run()
	//if err1 != nil {
	//	return  fmt.Errorf(fmt.Sprint(err1) + ": " + stderr.String())
	//}
	return exec.Command("bin/ceremony", "-config", path).Run()
}

func main() {
	// Create a SoftHSM slot for the root signing key
	rootKeySlot, err := createSlot("root signing key sm2")
	cmd.FailOnError(err, "failed creating softhsm2 slot for root key")

	// Generate the root signing key and certificate
	err = genKey("test/cert-ceremonies/root-ceremony-sm2.yaml", rootKeySlot)
	cmd.FailOnError(err, "failed to generate root key + root cert")

	// Create a SoftHSM slot for the intermediate signing key
	intermediateKeySlot, err := createSlot("intermediate signing key sm2")
	cmd.FailOnError(err, "failed to create softhsm2 slot for intermediate key")

	// Generate the intermediate signing key
	err = genKey("test/cert-ceremonies/intermediate-key-ceremony-sm2.yaml", intermediateKeySlot)
	cmd.FailOnError(err, "failed to generate intermediate key")

	// Create the A intermediate ceremony config file with the root
	// signing key slot and ID
	tmpRSAIntermediateA, err := rewriteConfig("test/cert-ceremonies/intermediate-ceremony-sm2.yaml", map[string]string{
		"SlotID":     rootKeySlot,
		"CertPath":   "/tmp/intermediate-cert-sm2-a.pem",
		"CommonName": "CA intermediate (sm2) A",
	})
	cmd.FailOnError(err, "failed to rewrite intermediate cert config with key ID")
	// Create the A intermediate certificate
	err = genCert(tmpRSAIntermediateA)
	cmd.FailOnError(err, "failed to generate intermediate cert1")

	// Create the B intermediate ceremony config file with the root
	// signing key slot and ID
	tmpRSAIntermediateB, err := rewriteConfig("test/cert-ceremonies/intermediate-ceremony-sm2.yaml", map[string]string{
		"SlotID":     rootKeySlot,
		"CertPath":   "/tmp/intermediate-cert-sm2-b.pem",
		"CommonName": "CA intermediate (sm2) B",
	})
	cmd.FailOnError(err, "failed to rewrite intermediate cert config with key ID")
	// Create the B intermediate certificate
	err = genCert(tmpRSAIntermediateB)
	cmd.FailOnError(err, "failed to generate intermediate cert2")

	// Create an OCSP response for the A intermediate
	tmpOCSPConfig, err := rewriteConfig("test/cert-ceremonies/intermediate-ocsp-sm2.yaml", map[string]string{
		"SlotID": rootKeySlot,
	})
	cmd.FailOnError(err, "failed to rewrite intermediate OCSP config with key ID")
	err = genCert(tmpOCSPConfig)
	cmd.FailOnError(err, "failed to generate intermediate OCSP response")
}


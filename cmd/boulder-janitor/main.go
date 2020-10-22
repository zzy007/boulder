package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"

	"github.com/letsencrypt/boulder/cmd"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to boulder-janitor configuration file")
	flag.Parse()

	configJSON, err := ioutil.ReadFile(*configPath)
	cmd.FailOnError(err, "Failed to read config file")

	var config Config
	err = json.Unmarshal(configJSON, &config)
	cmd.FailOnError(err, "Failed to parse JSON config")

	j, err := New(cmd.Clock(), config)
	cmd.FailOnError(err, "Failed to build janitor with config")

	j.Run()
}

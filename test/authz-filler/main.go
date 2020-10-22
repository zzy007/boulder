// A quick way to fill up a database with a large number of authz objects, in
// order to manually test the performance of the expired-authz-purger.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/sa"
)

type fillerConfig struct {
	Filler struct {
		cmd.DBConfig
		Parallelism uint
	}
}

type model struct {
	core.Authorization

	LockCol int
}

func main() {
	configPath := flag.String("config", "config.json", "Path to Boulder configuration file")
	flag.Parse()

	configJSON, err := ioutil.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file '%s': %s\n", *configPath, err)
		os.Exit(1)
	}

	var config fillerConfig
	err = json.Unmarshal(configJSON, &config)
	cmd.FailOnError(err, "Failed to parse config")

	// Configure DB
	dbURL, err := config.Filler.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	// Set max connections equal to parallelism.
	dbMap, err := sa.NewDbMap(dbURL, int(config.Filler.Parallelism))
	cmd.FailOnError(err, "Could not connect to database")

	dbMap.AddTableWithName(model{}, "pendingAuthorizations").SetKeys(false, "ID")
	span := 24 * time.Hour * 365
	start := time.Now().Add(-span)
	increment := time.Hour

	// Use a buffer with Parallelism entries so there's always work available.
	work := make(chan time.Time, config.Filler.Parallelism)
	go func() {
		for i := 0; i < int(span)/int(increment); i++ {
			expires := start.Add(time.Duration(i) * increment)
			// Arbitrarily make 30k entries per time chunk.
			for j := 0; j < 30000; j++ {
				work <- expires
			}
		}
	}()

	for i := 0; i < int(config.Filler.Parallelism); i++ {
		go func() {
			for expires := range work {
				err = dbMap.Insert(&model{
					core.Authorization{
						ID:             core.NewToken(),
						RegistrationID: 1,
						Expires:        &expires,
						Combinations:   [][]int{{1, 2, 3}},
						Status:         "pending",
						Identifier: identifier.ACMEIdentifier{
							Type:  "dns",
							Value: "example.com",
						},
					},
					0,
				})
				if err != nil {
					log.Print(err)
				}
			}
		}()
	}

	// Block forever.
	select {}
}

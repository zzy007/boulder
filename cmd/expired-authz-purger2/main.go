package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
	"github.com/prometheus/client_golang/prometheus"
)

type config struct {
	ExpiredAuthzPurger2 struct {
		cmd.DBConfig
		DebugAddr string
		Syslog    cmd.SyslogConfig
		Features  map[string]bool

		GracePeriod  cmd.ConfigDuration
		BatchSize    int
		WaitDuration cmd.ConfigDuration
	}
}

var deletedStat = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "eap2_authorizations_deleted",
		Help: "Number of authorizations the EAP2 tool has deleted.",
	},
)

func deleteExpired(clk clock.Clock, gracePeriod time.Duration, batchSize int, dbMap *db.WrappedMap) (int64, error) {
	expires := clk.Now().Add(-gracePeriod)
	res, err := dbMap.Exec(
		"DELETE FROM authz2 WHERE expires <= :expires LIMIT :limit",
		map[string]interface{}{
			"expires": expires,
			"limit":   batchSize,
		},
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func main() {
	singleRun := flag.Bool("single-run", false, "Exit after running first delete query instead of running indefinitely")
	configPath := flag.String("config", "config.json", "Path to Boulder configuration file")
	flag.Parse()

	configJSON, err := ioutil.ReadFile(*configPath)
	cmd.FailOnError(err, "Failed to read config file")
	var c config
	err = json.Unmarshal(configJSON, &c)
	cmd.FailOnError(err, "Failed to parse config file")
	err = features.Set(c.ExpiredAuthzPurger2.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	var logger blog.Logger
	if c.ExpiredAuthzPurger2.DebugAddr != "" {
		var stats prometheus.Registerer
		stats, logger = cmd.StatsAndLogging(c.ExpiredAuthzPurger2.Syslog, c.ExpiredAuthzPurger2.DebugAddr)
		stats.MustRegister(deletedStat)
	} else {
		logger = cmd.NewLogger(c.ExpiredAuthzPurger2.Syslog)
	}
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()

	dbURL, err := c.ExpiredAuthzPurger2.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, c.ExpiredAuthzPurger2.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")

	for {
		deleted, err := deleteExpired(clk, c.ExpiredAuthzPurger2.GracePeriod.Duration, c.ExpiredAuthzPurger2.BatchSize, dbMap)
		if err != nil {
			logger.Errf("failed to purge expired authorizations: %s", err)
			if !*singleRun {
				continue
			}
		}
		logger.Infof("deleted %d expired authorizations", deleted)
		if *singleRun {
			break
		}
		deletedStat.Add(float64(deleted))
		if deleted == 0 {
			// Nothing to do, sit around a while and wait
			time.Sleep(c.ExpiredAuthzPurger2.WaitDuration.Duration)
		}
	}
}

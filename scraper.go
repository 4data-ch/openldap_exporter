package openldap_exporter

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v2"
)

const (
	baseDN    = "cn=Monitor"
	opsBaseDN = "cn=Operations,cn=Monitor"

	monitorCounterObject = "monitorCounterObject"
	monitorCounter       = "monitorCounter"

	monitoredObject = "monitoredObject"
	monitoredInfo   = "monitoredInfo"

	monitorOperation   = "monitorOperation"
	monitorOpCompleted = "monitorOpCompleted"

	monitorReplicationFilter = "contextCSN"
	monitorReplication       = "monitorReplication"
)

type query struct {
	baseDN       string
	searchFilter string
	searchAttr   string
	metric       *prometheus.GaugeVec
	setData      func([]*ldap.Entry, *query)
}

var (
	monitoredObjectGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Subsystem: "openldap",
			Name:      "monitored_object",
			Help:      help(baseDN, objectClass(monitoredObject), monitoredInfo),
		},
		[]string{"dn"},
	)
	monitorCounterObjectGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Subsystem: "openldap",
			Name:      "monitor_counter_object",
			Help:      help(baseDN, objectClass(monitorCounterObject), monitorCounter),
		},
		[]string{"dn"},
	)
	monitorOperationGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Subsystem: "openldap",
			Name:      "monitor_operation",
			Help:      help(opsBaseDN, objectClass(monitorOperation), monitorOpCompleted),
		},
		[]string{"dn"},
	)
	bindCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "openldap",
			Name:      "bind",
			Help:      "successful vs unsuccessful ldap bind attempts",
		},
		[]string{"result"},
	)
	dialCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "openldap",
			Name:      "dial",
			Help:      "successful vs unsuccessful ldap dial attempts",
		},
		[]string{"result"},
	)
	scrapeCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "openldap",
			Name:      "scrape",
			Help:      "successful vs unsuccessful ldap scrape attempts",
		},
		[]string{"result"},
	)
	monitorReplicationGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Subsystem: "openldap",
			Name:      "monitor_replication",
			Help:      help(baseDN, monitorReplication),
		},
		[]string{"id", "type"},
	)
	queries = []*query{
		{
			baseDN:       baseDN,
			searchFilter: objectClass(monitoredObject),
			searchAttr:   monitoredInfo,
			metric:       monitoredObjectGauge,
			setData:      setValue,
		}, {
			baseDN:       baseDN,
			searchFilter: objectClass(monitorCounterObject),
			searchAttr:   monitorCounter,
			metric:       monitorCounterObjectGauge,
			setData:      setValue,
		},
		{
			baseDN:       opsBaseDN,
			searchFilter: objectClass(monitorOperation),
			searchAttr:   monitorOpCompleted,
			metric:       monitorOperationGauge,
			setData:      setValue,
		},
		{
			baseDN:       opsBaseDN,
			searchFilter: objectClass(monitorOperation),
			searchAttr:   monitorOpCompleted,
			metric:       monitorOperationGauge,
			setData:      setValue,
		},
	}
)

func init() {
	prometheus.MustRegister(
		monitoredObjectGauge,
		monitorCounterObjectGauge,
		monitorOperationGauge,
		monitorReplicationGauge,
		scrapeCounter,
		bindCounter,
		dialCounter,
	)
}

func help(msg ...string) string {
	return strings.Join(msg, " ")
}

func objectClass(name string) string {
	return fmt.Sprintf("(objectClass=%v)", name)
}

func setValue(entries []*ldap.Entry, q *query) {
	for _, entry := range entries {
		val := entry.GetAttributeValue(q.searchAttr)
		if val == "" {
			// not every entry will have this attribute
			continue
		}
		num, err := strconv.ParseFloat(val, 64)
		if err != nil {
			// some of these attributes are not numbers
			continue
		}
		q.metric.WithLabelValues(entry.DN).Set(num)
	}
}

func setReplicationValue(entries []*ldap.Entry, q *query) {
	for _, entry := range entries {
		val := entry.GetAttributeValue(q.searchAttr)
		if val == "" {
			// not every entry will have this attribute
			continue
		}
		fields := log.Fields{
			"filter": q.searchFilter,
			"attr":   q.searchAttr,
			"value":  val,
		}
		valueBuffer := strings.Split(val, "#")
		gt, err := time.Parse("20060102150405.999999Z", valueBuffer[0])
		if err != nil {
			log.WithFields(fields).WithError(err).Warn("unexpected gt value")
			continue
		}
		count, err := strconv.ParseFloat(valueBuffer[1], 64)
		if err != nil {
			log.WithFields(fields).WithError(err).Warn("unexpected count value")
			continue
		}
		sid := valueBuffer[2]
		mod, err := strconv.ParseFloat(valueBuffer[3], 64)
		if err != nil {
			log.WithFields(fields).WithError(err).Warn("unexpected mod value")
			continue
		}
		q.metric.WithLabelValues(sid, "gt").Set(float64(gt.Unix()))
		q.metric.WithLabelValues(sid, "count").Set(count)
		q.metric.WithLabelValues(sid, "mod").Set(mod)
	}
}

type Scraper struct {
	Net                string
	TLS                string
	InsecureSkipVerify bool
	TLSCA              string
	Addr               string
	User               string
	Pass               string
	Tick               time.Duration
	LdapSync           []string
	log                log.FieldLogger
	Sync               []string
}

func (s *Scraper) addReplicationQueries() {
	for _, q := range s.Sync {
		queries = append(queries,
			&query{
				baseDN:       q,
				searchFilter: objectClass("*"),
				searchAttr:   monitorReplicationFilter,
				metric:       monitorReplicationGauge,
				setData:      setReplicationValue,
			},
		)
	}
}

func (s *Scraper) Start(ctx context.Context) {
	s.log = log.WithField("component", "scraper")
	s.addReplicationQueries()
	address := fmt.Sprintf("%s://%s", s.Net, s.Addr)
	s.log.WithField("addr", address).Info("starting monitor loop")
	ticker := time.NewTicker(s.Tick)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.scrape()
		case <-ctx.Done():
			return
		}
	}
}

func (s *Scraper) scrape() {

	conn, err := s.getDialConnection()
	if err != nil {
		s.log.WithError(err).Error("Failed to establish connection")
		dialCounter.WithLabelValues("fail").Inc()
		return
	}
	defer conn.Close()

	err = s.bindUser(conn)
	if err != nil {
		s.log.WithError(err).Error("Failed to bind user")
		bindCounter.WithLabelValues("fail").Inc()
		return
	}
	bindCounter.WithLabelValues("ok").Inc()

	scrapeRes := "ok"
	for _, q := range queries {
		if err = scrapeQuery(conn, q); err != nil {
			s.log.WithError(err).WithField("filter", q.searchFilter).Warn("query failed")
			scrapeRes = "fail"
		}
	}
	scrapeCounter.WithLabelValues(scrapeRes).Inc()
}

func (s *Scraper) getDialConnection() (*ldap.Conn, error) {

	var conn *ldap.Conn

	if s.TLS != "" {
		tlsConfig, err := s.getTLSConfig()

		if err != nil {
			s.log.WithError(err).Error("Creating TLS Config failed")
			return nil, err
		}

		switch s.TLS {
		case "ldaps":
			conn, err = ldap.DialTLS(s.Net, s.Addr, tlsConfig)
			if err != nil {
				conn.Close()
				s.log.WithError(err).Error("Creating DialTLS connection failed")
				return nil, err
			}
		case "starttls":
			conn, err = ldap.Dial(s.Net, s.Addr)
			if err != nil {
				conn.Close()
				s.log.WithError(err).Error("Creating Dial connection failed")
				return nil, err
			}
			err = conn.StartTLS(tlsConfig)
			if err != nil {
				conn.Close()
				s.log.WithError(err).Error("Creating StartTLS connection failed")
				return nil, err
			}
		default:
			s.log.WithError(err).Error("Invalid settings for TLS")
			return nil, err
		}
	} else {
		conn, err := ldap.Dial(s.Net, s.Addr)
		if err != nil {
			conn.Close()
			s.log.WithError(err).Error("Dial failed")
			return nil, err
		}
	}

	return conn, nil
}

func (s *Scraper) getTLSConfig() (*tls.Config, error) {
	clientTLSConfig := ClientConfig{
		TLSCA:              s.TLSCA,
		InsecureSkipVerify: s.InsecureSkipVerify,
	}

	return clientTLSConfig.TLSConfig()
}

func (s *Scraper) bindUser(conn *ldap.Conn) error {
	if s.User != "" && s.Pass != "" {
		err := conn.Bind(s.User, s.Pass)
		if err != nil {
			return fmt.Errorf("Failed to bind user: %v", err)
		}
	}
	return nil
}

func scrapeQuery(conn *ldap.Conn, q *query) error {
	req := ldap.NewSearchRequest(
		q.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		q.searchFilter, []string{q.searchAttr}, nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		return err
	}
	q.setData(sr.Entries, q)
	return nil
}

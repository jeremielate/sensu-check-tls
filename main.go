package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"runtime/debug"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// check exit codes
const (
	OK = iota
	Warning
	Critical
	Unknown
)

func updateExitCode(newCode, exitCode int) (changed int) {
	if newCode > exitCode {
		exitCode = newCode
	}
	return exitCode
}

func main() {
	var (
		exitCode                                                            = OK
		lookupTimeout, connectionTimeout, warningValidity, criticalValidity time.Duration
		warningFlag, criticalFlag                                           uint
		version                                                             string
		printVersion                                                        bool
	)

	defer catchPanic()

	var host string
	var ips []net.IPAddr

	flag.StringVar(&host, "host", "", "the domain name of the host to check")
	flag.DurationVar(&lookupTimeout, "lookup-timeout", 10*time.Second, "timeout for DNS lookups - see: https://golang.org/pkg/time/#ParseDuration")
	flag.DurationVar(&connectionTimeout, "connection-timeout", 30*time.Second, "timeout connection - see: https://golang.org/pkg/time/#ParseDuration")
	flag.UintVar(&warningFlag, "w", 30, "warning validity in days")
	flag.UintVar(&criticalFlag, "c", 14, "critical validity in days")
	flag.BoolVar(&printVersion, "V", false, "print version and exit")
	flag.Parse()

	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&SimpleTextFormatter{DisableTimestamp: true})
	if printVersion {
		log.Infof("Version: %s", version)
		os.Exit(OK)
	}

	if host == "" {
		flag.Usage()
		log.Error("-host is required")
		os.Exit(Critical)
	}
	if warningFlag < criticalFlag {
		log.Warn("-c is higher than -w, i guess thats a bad i idea")
		exitCode = updateExitCode(Warning, exitCode)
	}

	warningValidity = time.Duration(warningFlag) * 24 * time.Hour
	criticalValidity = time.Duration(criticalFlag) * 24 * time.Hour

	ips = lookupIPWithTimeout(host, lookupTimeout)
	if len(ips) == 0 {
		os.Exit(Unknown)
	}
	log.Debugf("lookup result: %v", ips)

	for _, ip := range ips {
		dialer := net.Dialer{Timeout: connectionTimeout, Deadline: time.Now().Add(connectionTimeout + 5*time.Second)}
		connection, err := tls.DialWithDialer(&dialer, "tcp", fmt.Sprintf("[%s]:443", ip.IP), &tls.Config{ServerName: host})
		if err != nil {
			// catch missing ipv6 connectivity
			// if the ip is ipv6 and the resulting error is "no route to host", the record is skipped
			// otherwise the check will switch to critical
			if ip.IP.To4() == nil {
				switch err.(type) {
				case *net.OpError:
					// https://stackoverflow.com/questions/38764084/proper-way-to-handle-missing-ipv6-connectivity
					if err.(*net.OpError).Err.(*os.SyscallError).Err == syscall.EHOSTUNREACH {
						log.Infof("%-15s - ignoring unreachable IPv6 address", ip)
						continue
					}
				}
			}
			log.Errorf("%s: %s", ip, err)
			exitCode = updateExitCode(Critical, exitCode)
			continue
		}
		// rembember the checked certs based on their Signature
		checkedCerts := make(map[string]struct{})
		// loop to all certs we get
		// there might be multiple chains, as there may be one or more CAs present on the current system, so we have multiple possible chains
		for _, chain := range connection.ConnectionState().VerifiedChains {
			for _, cert := range chain {
				if _, checked := checkedCerts[string(cert.Signature)]; checked {
					continue
				}
				checkedCerts[string(cert.Signature)] = struct{}{}
				// filter out CA certificates
				if cert.IsCA {
					log.Debugf("%-15s - ignoring CA certificate %s", ip, cert.Subject.CommonName)
					continue
				}

				var certificateStatus int
				remainingValidity := cert.NotAfter.Sub(time.Now())
				if remainingValidity < criticalValidity {
					certificateStatus = Critical
				} else if remainingValidity < warningValidity {
					certificateStatus = Warning
				} else {
					certificateStatus = OK
				}
				exitCode = updateExitCode(certificateStatus, exitCode)
				logWithSeverity(certificateStatus, "%-15s - %s valid until %s (%s)", ip.IP, cert.Subject.CommonName, cert.NotAfter, formatDuration(remainingValidity))
			}
		}
		connection.Close()
	}
	os.Exit(exitCode)
}

func lookupIPWithTimeout(host string, timeout time.Duration) []net.IPAddr {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	r, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		log.Errorln(err)
		return []net.IPAddr{}
	}
	return r
}

func catchPanic() {
	if r := recover(); r != nil {
		log.Errorf("Panic: %+v", r)
		log.Error(string(debug.Stack()[:]))
		os.Exit(Critical)
	}
}

func formatDuration(in time.Duration) string {
	var daysPart, hoursPart, minutesPart, secondsPart string

	days := math.Floor(in.Hours() / 24)
	hoursRemaining := math.Mod(in.Hours(), 24)
	if days > 0 {
		daysPart = fmt.Sprintf("%.fd", days)
	} else {
		daysPart = ""
	}

	hours, hoursRemaining := math.Modf(hoursRemaining)
	minutesRemaining := hoursRemaining * 60
	if hours > 0 {
		hoursPart = fmt.Sprintf("%.fh", hours)
	} else {
		hoursPart = ""
	}

	if minutesRemaining > 0 {
		minutesPart = fmt.Sprintf("%.fm", minutesRemaining)
	}

	_, minutesRemaining = math.Modf(minutesRemaining)
	secondsRemaining := minutesRemaining * 60
	if secondsRemaining > 0 {
		secondsPart = fmt.Sprintf("%.fs", secondsRemaining)
	}

	return fmt.Sprintf("%s %s %s %s", daysPart, hoursPart, minutesPart, secondsPart)
}

func logWithSeverity(severity int, format string, args ...interface{}) {
	switch severity {
	case OK:
		log.Infof(format, args...)
	case Warning:
		log.Warnf(format, args...)
	case Critical:
		log.Errorf(format, args...)
	default:
		log.Panicf("Invalid severity %d", severity)
	}
}

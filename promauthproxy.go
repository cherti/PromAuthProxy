package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql"
)

var (
	// logger
	logInfo  = log.New(os.Stdout, "", 0)
	logDebug = log.New(os.Stdout, "DEBUG: ", 0)
	logError = log.New(os.Stdout, "ERROR: ", 0)

	// operation
	createEntry  = flag.Bool("new", false, "create new entry for passwordfile")
	injectTarget = flag.String("inject.label", "job", "label to inject or overwrite")

	// addresses and protocols
	outerAddress = flag.String("web.listen-address", ":8080", "address exposed to outside")
	innerAddress = flag.String("web.proxy-to", "127.0.0.1:9090", "address to proxy to")

	// HTTP basic auth
	passwordfile = flag.String("passwordfile", "users", "file with user-password-mapping")
	passwords    map[string][]byte

	// TLS
	crt = flag.String("crt", "", "path to TLS public key file for outer connection")
	key = flag.String("key", "", "path to TLS private key file for outer connection")

	// misc
	logTimestamps = flag.Bool("config.log-timestamps", false, "Log with timestamps")
	debug         = flag.Bool("config.debuglog", false, "Log with full details")
)

// director modifies the incoming http.request to go to the specified innerAddress
func director(r *http.Request) {
	r.URL.Scheme = "http"
	r.URL.Host = *innerAddress
}

// performRedirect redirects the incoming request to what is specified in the innerAddress-field
func performRedirect(w http.ResponseWriter, r *http.Request, username string) {

	newurl := r.URL.Path + "?"
	queries := r.URL.Query()
	for k, params := range queries {
		for _, param := range params {
			if k == "query" {
				newurl += fmt.Sprintf("%s=%s&", k, modifyQuery(param, username))
			} else {
				newurl += fmt.Sprintf("%s=%s&", k, param)
			}
		}
	}

	if *debug {
		logDebug.Println("old url:", r.URL)
		logDebug.Println("new url:", newurl)
	}

	u, _ := url.Parse(newurl)

	r.URL = u

	proxy := &httputil.ReverseProxy{Director: director}
	proxy.ServeHTTP(w, r)
}

// redirectAfterAuthCheck checks for correct authentication-credentials and either applies
// the intended redirect or asks for authentication-credentials once again.
func redirectAfterAuthCheck(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	pass_correct := subtle.ConstantTimeCompare(hashPassword(p), passwords[u]) == 1

	if ok && pass_correct {
		performRedirect(w, r, u)
	} else {
		// send out unauthenticated response asking for basic auth
		// (to make sure people that mistyped can retry)
		w.Header().Set("WWW-Authenticate", `Basic realm="all"`)
		http.Error(w, "Unauthenticated", 401)
	}
}

func hashPassword(pw string) []byte {
	pwbyte := []byte(pw)
	pwhash := sha256.Sum256(pwbyte)
	return pwhash[:]
}

func createPasswordEntry() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintf(os.Stderr, "Enter username: ")
	user, _ := reader.ReadString('\n')
	fmt.Fprintf(os.Stderr, "Enter password: ")
	pass, _ := reader.ReadString('\n')
	pwhash := hashPassword(strings.Trim(pass, "\n "))
	password := base64.StdEncoding.EncodeToString(pwhash)
	fmt.Println(strings.Trim(user, "\n "), password)

}

func modifyQuery(q, injectable string) string {
	expr, err := promql.ParseExpr(q)
	if err != nil {
		log.Fatal("ERROR, invalid query:", err)
	}
	promql.Inspect(expr, rewriteLabelsets(injectable))
	return expr.String()
}

func rewriteLabelsets(injected string) func(n promql.Node, path []promql.Node) bool {
	return func(n promql.Node, path []promql.Node) bool {
		switch n := n.(type) {
		case *promql.MatrixSelector:
			// check if label is already present, replace in this case
			found := false
			for i, l := range n.LabelMatchers {
				if l.Type == labels.MatchEqual {
					if l.Name == *injectTarget {
						l.Value = injected
						found = true
					}
				} else { // drop matcher if not MatchEqual
					n.LabelMatchers = append(n.LabelMatchers[:i], n.LabelMatchers[i+1:]...)
				}
			}

			// if label is not present, inject it
			if !found {
				joblabel, err := labels.NewMatcher(labels.MatchEqual, *injectTarget, injected)
				if err != nil {
					//handle
				}
				n.LabelMatchers = append(n.LabelMatchers, joblabel)

			}
		case *promql.VectorSelector:
			// check if label is already present, replace in this case
			found := false
			for i, l := range n.LabelMatchers {
				if l.Type == labels.MatchEqual {
					if l.Name == *injectTarget {
						l.Value = injected
						found = true
					}
				} else { // drop matcher if not MatchEqual
					n.LabelMatchers = append(n.LabelMatchers[:i], n.LabelMatchers[i+1:]...)
				}
			}
			// if label is not present, inject it
			if !found {
				joblabel, err := labels.NewMatcher(labels.MatchEqual, *injectTarget, injected)
				if err != nil {
					//handle
				}
				n.LabelMatchers = append(n.LabelMatchers, joblabel) // this doesn't compile with compiler error
			}
		}
		return true
	}
}

func main() {
	flag.Parse()
	if *logTimestamps {
		logInfo.SetFlags(3)
		logDebug.SetFlags(3)
		logError.SetFlags(3)
	}

	passwords = make(map[string][]byte)

	if *createEntry {
		createPasswordEntry()
		os.Exit(0)
	}

	// load passwords
	logInfo.Println("reading user-password mappinggs from", *passwordfile)

	file, err := os.Open(*passwordfile)
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		res := strings.Split(line, " ")
		if len(res) != 2 {
			logError.Println("Error parsing line:", line)
			continue
		}
		pwbytes, err := base64.StdEncoding.DecodeString(res[1])
		if err != nil {
			logError.Println("Error decoding line:", line)
			continue
		}
		passwords[res[0]] = pwbytes
	}
	file.Close()

	logInfo.Println("starting redirector from", *outerAddress, "to", *innerAddress)
	http.HandleFunc("/", redirectAfterAuthCheck)

	useTLS := *crt != "" && *key != ""
	if useTLS {
		logInfo.Println("TLS enabled")
		logError.Fatal(http.ListenAndServeTLS(*outerAddress, *crt, *key, nil))
	} else {
		logInfo.Println("TLS disabled")
		logError.Fatal(http.ListenAndServe(*outerAddress, nil))
	}
}

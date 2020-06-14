package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"golang.org/x/net/html"
)

var (
	// logger
	logInfo  = log.New(os.Stdout, "", 0)
	logDebug = log.New(os.Stdout, "DEBUG: ", 0)
	logError = log.New(os.Stdout, "ERROR: ", 0)

	// operation
	injectTarget       = flag.String("inject.label", "job", "label to inject or overwrite")
	injectSourceHeader = flag.String("inject.source", "X-prometheus-injectable", "HTTP header specifying label to-be-injected")

	// addresses and protocols
	outerAddress = flag.String("web.listen-address", ":8080", "address exposed to outside")
	innerAddress = flag.String("web.proxy-to", "127.0.0.1:9090", "address to proxy to")

	// misc
	logTimestamps = flag.Bool("log.timestamps", false, "Log with timestamps")
	debug         = flag.Bool("log.debug", false, "Log with full details")
)

type silence struct {
	Id        string
	CreatedBy string
	Comment   string
	StartsAt  string
	EndsAt    string
	Matchers  []matcher
}

type matcher struct {
	Name    string
	Value   string
	IsRegex bool
}

// director modifies the incoming http.request to go to the specified innerAddress
func director(r *http.Request) {
	r.URL.Scheme = "http"
	r.URL.Host = *innerAddress
}

// injectLabelIntoNewSilence modifies a new silence request to the alertmanager such that
// it is guaranteed to contain the to-be-injected label appropriately
func injectLabelIntoNewSilence(r *http.Request, label string) (io.ReadCloser, int64) {
	// modify POST-request with new silences to alertmanager to inject labelmatcher
	headerCL := r.Header["Content-Length"]
	var cl int64
	if len(headerCL) > 0 {
		c, err := strconv.ParseInt(headerCL[0], 10, 64)
		if err != nil {
			logError.Println(err)
		} else {
			cl = c // actually use the contentlength != 0
		}
	}
	bodycontent := make([]byte, cl)
	n, err := r.Body.Read(bodycontent)
	if err != nil && err != io.EOF {
		logError.Println(err, "; bytes read when error occurred:", n)
	}
	var s silence
	err = json.Unmarshal(bodycontent, &s)
	var b []byte
	if err != nil {
		logError.Println(err)
		b = []byte("") // just put garbage in, Prometheus will do the rest (i.e. nothing)
	} else {
		// inject targetlabel as additional filter
		s.Matchers = append(s.Matchers, matcher{*injectTarget, label, false})
		b, _ = json.Marshal(s)
	}
	return ioutil.NopCloser(bytes.NewReader(b)), int64(len(b))
}

// injectLabelIntoQuery injects the specified label into the GET-Parameter denoted by queryparam
// in the parameter set of the supplied requespointer
func injectLabelIntoQuery(r *http.Request, GETparam, label string, createIfAbsent bool, ensureBracketEnclose bool) {
	found := false

	queryparams := r.URL.Query()
	newqueryparams := url.Values{}
	for k, params := range queryparams {
		for _, param := range params {
			if k == GETparam {
				if ensureBracketEnclose && !strings.HasSuffix(param, "}") {
					newqueryparams.Add(k, modifyQuery("{"+param+"}", label))
				} else {
					newqueryparams.Add(k, modifyQuery(param, label))
				}
				found = true
			} else {
				newqueryparams.Add(k, param)
			}
		}
	}

	if !found && createIfAbsent {
		p := r.URL.Query()
		if ensureBracketEnclose {
			p.Add(GETparam, "{"+*injectTarget+"="+label+"}")
		} else {
			p.Add(GETparam, *injectTarget+"="+label)
		}
		r.URL.RawQuery = p.Encode()
	} else {
		r.URL.RawQuery = newqueryparams.Encode()
	}
}

// bufferedResponseWriter behaves like a responseWriter, but bufferes bytes written to it for later
// readout and modification. It is intended that those modified bytes are then written to the
// responseWriter used when creating the bufferedResponseWriter.
type bufferedResponseWriter struct {
	http.ResponseWriter
	buf bytes.Buffer
}

// Write writes the given bytes to an internal buffer for later read-out.
func (w *bufferedResponseWriter) Write(p []byte) (n int, err error) {
	return w.buf.Write(p)
}

// performRedirect redirects the incoming request to what is specified in the innerAddress-field and
// modifies all query-expressions encoded in the URL to contain the required labelmatcher
func performRedirectWithInject(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		logDebug.Println("old url:", r.URL)
	}

	injectedLabel := r.Header.Get(*injectSourceHeader)

	switch r.URL.Path {
	case "/api/v1/silences":
		switch r.Method {
		case "POST":
			r.Body, r.ContentLength = injectLabelIntoNewSilence(r, injectedLabel)
		case "GET":
			injectLabelIntoQuery(r, "filter", injectedLabel, true, true)
		}
	case "/api/v2/silences":
		switch r.Method {
		case "POST":
			r.Body, r.ContentLength = injectLabelIntoNewSilence(r, injectedLabel)
		case "GET":
			injectLabelIntoQuery(r, "filter", injectedLabel, true, false)
		}
	case "/api/v1/series":
		injectLabelIntoQuery(r, "match[]", injectedLabel, true, false)
	case "/api/v1/labels":
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Due to potential cross-tenant-information-leakage this API is currently unavailable."))
	case "/api/v1/alerts": // AM
		switch r.Method {
		case "GET":
			injectLabelIntoQuery(r, "filter", injectedLabel, true, true)
		}
	case "/api/v2/alerts": // AM
		switch r.Method {
		case "GET":
			injectLabelIntoQuery(r, "filter", injectedLabel, true, true)
		}
	case "/federate":
		injectLabelIntoQuery(r, "match[]", injectedLabel, true, true)
	case "/service-discovery":
		r.URL.Path = "/targets"
	default: // targeted at "/api/v1/silences"
		// modify Prometheus-GET-Queries to inject label into PromQL-Expressions
		injectLabelIntoQuery(r, "query", injectedLabel, false, false)
	}

	if r.Method == "GET" {
		logDebug.Println("new url:", r.URL)
	}

	proxy := &httputil.ReverseProxy{Director: director}
	if *injectTarget == "job" {
		// if injection is made into the job-label we assume this is used as a user-separation
		// mechanism, therefore we can use that assumption to filter the targets and alerts accordingly
		switch r.URL.Path {
		case "/targets":
			bw := &bufferedResponseWriter{ResponseWriter: w}
			proxy.ServeHTTP(bw, r)
			w.Write(filterTargets(string(bw.buf.Bytes()), injectedLabel))
			return
		case "/alerts":
			bw := &bufferedResponseWriter{ResponseWriter: w}
			proxy.ServeHTTP(bw, r)
			w.Write(rewriteAlerts(string(bw.buf.Bytes()), injectedLabel))
			return
		}
	}
	proxy.ServeHTTP(w, r)
}

// filterTargets removes all targets that do not belong to the logged-in user
// from the targets-list
func filterTargets(page string, injectedLabel string) []byte {
	doc, err := html.Parse(strings.NewReader(page))
	if err != nil {
		logError.Println(err)
		return []byte("500 - Something went wrong. If this problem persists, please contact your operator.")
	}

	var f func(*html.Node, string)
	f = func(n *html.Node, token string) {
		if n.Type == html.ElementNode && n.Data == "h2" {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Data == "a" {
					for _, a := range c.Attr {
						if a.Key == "id" && a.Val != "job-"+token {
							for followup := n.NextSibling; followup != nil; followup = followup.NextSibling {
								if followup.Data == "table" {
									n.Parent.RemoveChild(followup)
									n.Parent.RemoveChild(n)
									break
								}
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c, token)
		}
	}
	f(doc, injectedLabel)
	buf := new(bytes.Buffer)
	html.Render(buf, doc)
	return buf.Bytes()
}

// rewriteAlerts rewrites the alert-page in a way, that users always only see their alerts
// but other people's alerts always seem green and fine (except for reordering).
func rewriteAlerts(page, injectedLabel string) []byte {

	doc, err := html.Parse(strings.NewReader(page))
	if err != nil {
		logError.Println(err)
		return []byte("500 - Something went wrong. If this problem persists, please contact your operator.")
	}

	var f func(*html.Node, string)

	f = func(n *html.Node, token string) {
		if n.Type == html.ElementNode && n.Data == "tr" {
			class := getClass(n)
			if class == "warning alert_header" || class == "danger alert_header" {
				rewriteAlert(n, token)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c, token)
		}
	}

	f(doc, injectedLabel)
	buf := new(bytes.Buffer)
	html.Render(buf, doc)
	return buf.Bytes()
}

// rewriteAlert takes a html-alert-node and rewrites it according to the given token.
func rewriteAlert(n *html.Node, injectedLabel string) {
	for c1 := n.FirstChild; c1 != nil; c1 = c1.NextSibling {
		if c1.Data == "td" {
			for c2 := c1.FirstChild; c2 != nil; c2 = c2.NextSibling {
				if c2.Data == "b" {
					if strings.HasPrefix(c2.FirstChild.Data, injectedLabel) {
						return
					}

					// set alert count to zero
					c2.NextSibling.Data = " (0 active)"
				}

				//fmt.Println(c2.Data) //.NextSibling.NextSibling.Data) //.FirstChild.Data)
				//fmt.Println(c.FirstChild.Data) //.NextSibling.NextSibling.Data) //.FirstChild.Data)
			}
		}
	}
	// set class to success alert header
	for _, a := range n.FirstChild.Attr {
		fmt.Println(a.Key, a.Val)
	}
	for i, a := range n.Attr {
		if a.Key == "class" {
			n.Attr[i] = html.Attribute{a.Namespace, a.Key, "success alert_header"}
		}
	}
	for c := n.NextSibling; c != nil; c = c.NextSibling {
		if getClass(c) == "alert_details" {

			// drop alert details/labels
			for c1 := c.FirstChild; c1 != nil; c1 = c1.NextSibling {
				for c2 := c1.FirstChild; c2 != nil; c2 = c2.NextSibling {
					if c2.Data == "table" && getClass(c2) == "table table-bordered table-hover table-condensed alert_elements_table" {
						c2.Parent.RemoveChild(c2)
					}
				}
			}
			break
		}
	}
}

// getClass returns the class of an html-node if there is any, otherwise an empty string
func getClass(n *html.Node) string {
	for _, a := range n.Attr {
		if a.Key == "class" {
			return a.Val
		}
	}
	return ""
}

// hashPasswords provides the password-encoding used in PromAuthProxy.
func hashPassword(pw string) []byte {
	pwbyte := []byte(pw)
	pwhash := sha256.Sum256(pwbyte)
	return pwhash[:]
}

// createPasswordEntry reads a username and password from the commandline and
// creates and prints a valid passwordfile-entry for these credentials.
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

// modifyQuery modifies a given Prometheus-query-expression to contain the required
// labelmatchers.
func modifyQuery(q, injectable string) string {
	logDebug.Println("Incoming query:", q)
	expr, err := parser.ParseExpr(q)
	if err != nil {
		// Prometheus will return a failure as well and not hand out any results
		// but instead define the syntax error. The corrected query will then
		// evaluate correctly and the appropriate label injected
		return q
	}
	parser.Inspect(expr, rewriteLabelsets(injectable))
	q = expr.String()
	logDebug.Println("Outgoing query:", q)
	return q
}

// rewriteLabelsets returns the function that will be used to walk the
// Prometheus-query-expression-tree and rewrites the necessary selectors with
// to the specified injected label before the query is handed over to Prometheus.
func rewriteLabelsets(injected string) func(n parser.Node, path []parser.Node) error {
	return func(n parser.Node, path []parser.Node) error {
		switch n := n.(type) {
		case *parser.VectorSelector:
			// check if label is already present, replace in this case
			for i, l := range n.LabelMatchers {
				// drop label matcher to be replaced if present
				if l.Name == *injectTarget {
					if i+1 >= len(n.LabelMatchers) { // if it's the last matcher in labelMatchers
						n.LabelMatchers = n.LabelMatchers[:i]
					} else {
						n.LabelMatchers = append(n.LabelMatchers[:i], n.LabelMatchers[i+1:]...)
					}
				}
			}

			// inject desired label
			injectedLabelMatcher, err := labels.NewMatcher(labels.MatchEqual, *injectTarget, injected)
			if err != nil {
				// handle appropriately
			}
			n.LabelMatchers = append(n.LabelMatchers, injectedLabelMatcher)
		}
		return nil
	}
}

func main() {
	flag.Parse()
	if *logTimestamps {
		logInfo.SetFlags(3)
		logDebug.SetFlags(3)
		logError.SetFlags(3)
	}

	if !*debug {
		logDebug.SetOutput(ioutil.Discard)
	}

	logInfo.Println("starting redirector from", *outerAddress, "to", *innerAddress)
	http.HandleFunc("/", performRedirectWithInject)
	logError.Fatal(http.ListenAndServe(*outerAddress, nil))
}

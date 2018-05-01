# PromAuthProxy

PromAuthProxy is an Authentication-Proxy for the [Prometheus Monitoring System](https://prometheus.io).

It enables to use a single Prometheus-instance with multiple users, such that each user can query the Prometheus instance, but will only see their own metrics.

## How it works

### with Prometheus

PromAuthProxy is a proxy that sits before the Prometheus-intstance in question and currently supporting HTTP Basic Auth as the authentication method of choice to allow access to the Prometheus behind it.
To ensure that users only see their own metrics, PromAuthProxy takes a target label (by default the `job`-label), inspects the query that is submitted to the prometheus and ensures that every query includes the target label set to the Basic-Auth-username, either by injecting it if not present or overwriting if specified differently.
Currently, the target-list and the rules-list are not filtered as this would require modifying the HTML response.

### with Alertmanager

Similar to the Prometheus-Setup, PromAuthProxy injects the target-label with the login name as value into every query and inspection of a silence, as well as into the generation of a new silence.
This means that users can only see alerts with the target-label set to their username and no other and can only generate new silences with the according matcher included (actually users can generate a silence without and the matcher is injected by PromAuthProxy automatically).
Therefore with PromAuthProxy before users should not be able to tell if other people are using the same alertmanager.

## Building and running

### manually

    # actually build and run
    git clone https://github.com/cherti/promauthproxy.git
    cd promauthproxy
    go get ./...
    go build promauthproxy.go
    ./promauthproxy


### automatically using go-toolchain

    go get -u "github.com/cherti/promauthproxy"
    ./promauthproxy

## How to use it

By default, promauthproxy reads a `users`-file in the same directory as it is started in.
Then it creates a reverse HTTP proxy between `:8080` and `127.0.0.1:9090`, which in the default configuration proxies and requests from port 8080 to the Prometheus that (hopefully) listens on `127.0.0.1:9090` and the Prometheus-Interface is visible through the proxy.
All requests made there are transparently handed over to the Prometheus-instance after the necessary label-injections have been performed and Prometheus' response will be transparently returned as well.

### commandline flag reference

    -config.debuglog
      	Log with full details
    -config.log-timestamps
      	Log with timestamps
    -crt string
      	path to TLS public key file for outer connection
    -key string
      	path to TLS private key file for outer connection
    -inject.label string
      	target label to inject or overwrite (default "job")
    -passwordfile string
      	file with user-password-mapping (default "users")
    -new
      	create new entry for passwordfile
    -web.listen-address string
      	address exposed to outside (default ":8080")
    -web.proxy-to string
      	address to proxy to (default "127.0.0.1:9090")

With the `-new`-flag provided, PromAuthProxy will ask for a username and a password and will output the resulting line for the passwordfile.
It can, for example, be used via

    promauthproxy -new >> passwordfile

and will write the line in question (and only this line) into the passwordfile as an additional line this way.
The output-line can also be copied to the file manually, of course.

## License

This works is released under the [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.txt). You can find a copy of this license in the file `LICENSE` or at https://www.gnu.org/licenses/gpl-3.0.txt.

## Remark

This is currently beta software. Until version 1.0 will be reached, backwards incompatible breaks might still occur, although they are avoided if possible. Especially the config format might still be subject to change.

# PromAuthProxy

PromAuthProxy is an Authentication-Proxy for the [Prometheus Monitoring System](https://prometheus.io).

It enables to use a single Prometheus-instance with multiple users, such that each user can query the Prometheus instance, but will only see their own metrics.

## How it works

PromAuthProxy is a proxy that sits before the Prometheus-intstance in question and currently supporting HTTP Basic Auth as the authentication method of choice to allow access to the Prometheus behind it.
To ensure that users only see their own metrics, PromAuthProxy takes a target label (by default the `job`-label), inspects the query that is submitted to the prometheus and ensures that every query includes the target label set to the Basic-Auth-username, either by injecting it if not present or overwriting if specified differently.

## Building and running

### manually

    # actually build and run
    git clone https://github.com/cherti/promauthproxy.git
    cd promauthproxy
    go get ./...
    go build promauthproxy.go
    ./promauthproxy


### automatically using go-toolchain

    go get -u "github.com/cherti/mailexporter"
    ./mailexporter

## How to use it

`promauthproxy...`

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

This works is released under the [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.txt). You can find a copy of this license at https://www.gnu.org/licenses/gpl-3.0.txt.

## Remark

This is currently beta software. Until version 1.0 will be reached, backwards incompatible breaks might still occur, although they are avoided if possible. Especially the config format might still be subject to change.

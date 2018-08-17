# PromAuthProxy

PromAuthProxy is an Authentication-Proxy for the [Prometheus Monitoring System](https://prometheus.io).

It enables to use a single Prometheus-instance with multiple users, such that each user can query the Prometheus instance, but will only see their own metrics.

## How it works

### with Prometheus

PromAuthProxy is a proxy that sits before the Prometheus-intstance in question. To ensure that users only see their own metrics, PromAuthProxy takes a target label (by default the `job`-label), inspects the query that is submitted to the prometheus and ensures that every query includes the target label set to the value of the HTTP-Header (by default) `X-prometheus-injectable`, either by injecting it if not present or overwriting if specified differently.
The `X-Prometheus-injectable` has to be set by a previous component, for example an nginx providing HTTP basic auth or any other component that is able to set such an HTTP-Header. The label used is freely choosable, but should of course be present in the time series (to be ensured via the prometheus-configuration).

In addition to this, when the label `job` is used for such multi-tenancy separation PromAuthProxy also filteres the target list as well as the alerts view as long as the alert names start with the injected job label (such as `"username: CPUbusy"`).


### with Alertmanager

Similar to the Prometheus-Setup, PromAuthProxy injects the target-label into every query and inspection of a silence, as well as into the generation of a new silence.
This means that users can only see alerts with the target-label set to their username and no other and can only generate new silences with the according matcher included (actually users can generate a silence without and the matcher is injected by PromAuthProxy automatically).
Therefore with PromAuthProxy before users should not be able to tell if other people are using the same alertmanager except for the names in the dropdown.

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

PromAuthProxy is intended as a proxy between a Prometheus Server/Alertmanager and another proxy tasked with authenticating the user and injecting the required label into the HTTP-request (e.g. an nginx with HTTP basic auth in the most simple case).

### commandline flag reference

    -config.debuglog
      	Log with full details
    -config.log-timestamps
      	Log with timestamps
    -inject.label string
      	target label to inject or overwrite (default "job")
    -inject.source string
      	HTTP header specifying label to-be-injected (default "X-prometheus-injectable")
    -web.listen-address string
      	address exposed to outside (default ":8080")
    -web.proxy-to string
      	address to proxy to (default "127.0.0.1:9090")

## License

This works is released under the [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.txt). You can find a copy of this license in the file `LICENSE` or at https://www.gnu.org/licenses/gpl-3.0.txt.

## Remark

This is currently beta software. Until version 1.0 will be reached, backwards incompatible breaks might still occur, although they are avoided if possible. Especially the config format might still be subject to change.

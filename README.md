# GoRTR

GoRTR is an open-source implementation of RPKI to Router protocol (RFC 6810) using the [the Go Programming Language](http://golang.org/).

* `/lib` contains a library to create your own server and client.
* `/prefixfile` contains the structure of a JSON export file and signing capabilities.
* `/cmd/gortr/gortr.go` is a simple implementation that fetches a list and offers it to a router.
* `/cmd/rtrdump/rtrdump.go` allows.

## Disclaimer

_This software comes with no warranty._

## Features of the server

* Refreshes a JSON list of prefixes (from either Cloudflare or a RIPE Validator)
* Prometheus metrics
* Lightweight
* TLS
* Signature verification and expiration control

## Features of the extractor

* Generate a list of prefixes sent via RTR (similar to Cloudflare JSON input, or RIPE RPKI Validator)
* Lightweight
* TLS

## Features of the API

* Protocol v0 of [RFC6810](https://tools.ietf.org/html/rfc6810)
* Protocol v1 of [RFC8210](https://tools.ietf.org/html/rfc8210)
* Event-driven API
* TLS

## To start developing

You need a working [Go environment](https://golang.org/doc/install) (1.10 or newer).
This project also uses [Go Modules](https://github.com/golang/go/wiki/Modules).

```bash
$ git clone git@github.com:cloudflare/gortr.git && cd gortr
$ go build cmd/gortr/gortr.go
```

## Install it

```bash
$ go get github.com/cloudflare/gortr/cmd/gortr
```

Copy `cf.pub` to your local directory if you want to use Cloudflare's signed JSON file.

Create TLS certificates if you want to use the TLS feature:

```bash
$ openssl ecparam -genkey -name prime256v1 -noout -outform pem > private.pem
$ openssl req -new -x509 -key private.pem -out server.pem
```

If you want to sign your list of prefixes, generate an ECDSA key (similar to the first command above).
Then generate the public key.
```bash
$ openssl ec -in private.pem -pubout -outform pem > public.pem
```

## Run it

Once you have a binary, from either the `~/go/bin/` (if you did `go get` or `go build`)
or the [Releases page](https://github.com/cloudflare/gortr/releases):

```bash
$ ./gortr -bind 127.0.0.1:8282
```

Make sure cf.pub is in the current directory. Or pass `-verify.key=path/to/cf.pub`

## Debug the content

```bash
$ ./rtrdump -connect 127.0.0.1:8282 -file debug.json
```

### Data sources

Use your own validator, as long as the JSON source follows the following schema:
```
{
  "roas": [
    {
      "prefix": "10.0.0.0/24",
      "maxLength": 24,
      "asn": "AS65001"
    },
    ...
  ]
}
```

* [**Cloudflare**](https://rpki.cloudflare.com/rpki.json) *(list curated, signed, compressed and cached in +160 PoPs)*
* **Third-party RIPE Validators:**
  * [NTT](https://rpki.gin.ntt.net/api/export.json)
  * [RIPE](http://localcert.ripe.net:8088/export.json)
  * [LACNIC](http://ripeval.labs.lacnic.net:8080/export.json)
  
To use a data source that do not contains signatures or validity information, pass:
`-verify=false -checktime=false`

Cloudflare's prefix list removes duplicates and entries that are not routed on the Internet (>/24 IPv4 and >/48 IPv6).

### Configure on Juniper

Configure a session to the RTR server
```
louis@router> show configuration routing-options validation
group TEST-RPKI {
    session 192.168.1.100 {
        port 8282;
    }
}
```
Add policies to validate or invalidate prefixes
```
louis@router> show configuration policy-options policy-statement STATEMENT-EXAMPLE
term RPKI-TEST-VAL {
    from {
        protocol bgp;
        validation-database valid;
    }
    then {
        validation-state valid;
        next term;
    }
}
term RPKI-TEST-INV {
    from {
        protocol bgp;
        validation-database invalid;
    }
    then {
        validation-state invalid;
        reject;
    }
}
```
Display status of the session to the RTR server.
```
louis@router> show validation session 192.168.1.100 detail
Session 192.168.1.100, State: up, Session index: 1
  Group: TEST-RPKI, Preference: 100
  Port: 8282
  Refresh time: 300s
  Hold time: 600s
  Record Life time: 3600s
  Serial (Full Update): 1
  Serial (Incremental Update): 1
    Session flaps: 2
    Session uptime: 00:25:07
    Last PDU received: 00:04:50
    IPv4 prefix count: 46478
    IPv6 prefix count: 8216
```
Show content of the database
```
louis@router> show validation database brief
RV database for instance master

Prefix                 Origin-AS Session                                 State   Mismatch
1.0.0.0/24-24              13335 192.168.1.100                           valid
1.1.1.0/24-24              13335 192.168.1.100                           valid
```

## License

Licensed under the BSD 3 License.

# GoRTR

Go implementation of a RPKI to Router protocol.

* `/lib` contains a library to create your own server and client.
* `gortr.go` is a simple implementation that fetches a list and offers it to a router.

## Features of the server

* Refreshes a JSON list of prefixes (from either Cloudflare or a RIPE Validator)
* Prometheus metrics
* Lightweight
* TLS

## Features of the API

* Protocol v0 of [RFC6810](https://tools.ietf.org/html/rfc6810)
* Protocol v1 of [draft-ietf-sidr-rpki-rtr-rfc6810-bis-09](https://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-rfc6810-bis-09)
* Event-driven API
* TLS

## Run it

```
$ ./gortr -bind 127.0.0.1:8282 -cache datasource
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

* [**Cloudflare**](https://rpki.cloudflare.com/rpki.json) *(list curated, compressed and cached in +150 PoPs)*
* **Third-party RIPE Validators:**
  * [NTT](https://rpki.gin.ntt.net/api/export.json)
  * [RIPE](http://localcert.ripe.net:8088/export.json)
  * [LACNIC](http://ripeval.labs.lacnic.net:8080/export.json)

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

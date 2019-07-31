# GoRTR

GoRTR is an open-source implementation of RPKI to Router protocol (RFC 6810) using the [the Go Programming Language](http://golang.org/).

* `/lib` contains a library to create your own server and client.
* `/prefixfile` contains the structure of a JSON export file and signing capabilities.
* `/cmd/gortr/gortr.go` is a simple implementation that fetches a list and offers it to a router.
* `/cmd/rtrdump/rtrdump.go` allows copying the PDUs sent by a RTR server as a JSON file.

## Disclaimer

_This software comes with no warranty._

## Features of the server

* Refreshes a JSON list of prefixes (from either Cloudflare or a RIPE Validator)
* Prometheus metrics
* Lightweight
* TLS
* SSH
* Signature verification and expiration control

## Features of the extractor

* Generate a list of prefixes sent via RTR (similar to Cloudflare JSON input, or RIPE RPKI Validator)
* Lightweight
* TLS
* SSH

## Features of the API

* Protocol v0 of [RFC6810](https://tools.ietf.org/html/rfc6810)
* Protocol v1 of [RFC8210](https://tools.ietf.org/html/rfc8210)
* Event-driven API
* TLS
* SSH

## To start developing

You need a working [Go environment](https://golang.org/doc/install) (1.10 or newer).
This project also uses [Go Modules](https://github.com/golang/go/wiki/Modules).

```bash
$ git clone git@github.com:cloudflare/gortr.git && cd gortr
$ go build cmd/gortr/gortr.go
```

## With Docker

If you do not want to use Docker, please go to the next section.

If you have **Docker**, you can start GoRTR with `docker run -ti -p 8082:8082 cloudflare/gortr`.
The containers contains Cloudflare's public signing key and an testing ECDSA private
key for the SSH server.

It will automatically download Cloudflare's prefix list and use the public key
to validate it.

You can now use any CLI attributes as long as they are after the image name:
```bash
$ docker run -ti -p 8083:8083 cloudflare/gortr -bind :8083
```

If you want to build your own image of GoRTR:
```bash
$ docker build -t mygortr -f Dockerfile.gortr.prod .
$ docker run -ti mygortr -h
```
It will download the code from GitHub and compile it with Go and also generate an ECDSA key for SSH.

Please note: if you plan to use SSH with Cloudflare's default container (`cloudflare/gortr`),
replace the key `private.pem` since it is a testing key that has been published.
An example is given below:

```bash
$ docker run -ti -v $PWD/mynewkey.pem:/private.pem cloudflare/gortr -ssh.bind :8083
```

## Install it

There are a few solutions to install it.

Go can directly fetch it from the source

```bash
$ go get github.com/cloudflare/gortr/cmd/gortr
```

Copy `cf.pub` to your local directory if you want to use Cloudflare's signed JSON file.

You can use the Makefile (by default it will be compiled for Linux, add `GOOS=darwin` for Mac)

```bash
$ make dist-key build-gortr
```

The compiled file will be in `/dist`.

Or you can use a package (or binary) file from the [Releases page](https://github.com/cloudflare/gortr/releases):
```bash
$ sudo dpkg -i gortr[...].deb
$ sudo systemctl start gortr
```

If you want to sign your list of prefixes, generate an ECDSA key.
Then generate the public key to be used in GoRTR.
You will have to setup your validator to use this key or have another
tool to sign the JSON file before passing it to GoRTR.
```bash
$ openssl ecparam -genkey -name prime256v1 -noout -outform pem > private.pem
$ openssl ec -in private.pem -pubout -outform pem > public.pem
```

## Run it

Once you have a binary:

```bash
$ ./gortr -tls.bind 127.0.0.1:8282
```

Make sure cf.pub is in the current directory. Or pass `-verify.key=path/to/cf.pub`

## Package it

If you want to package it (deb/rpm), you can use the pre-built docker-compose file.

```bash
$ docker-compose -f docker-compose-pkg.yml up
```

You can find both files in the `dist/` directory.

### Usage with a proxy

This was tested with a basic Squid proxy. The `User-Agent` header is passed
in the CONNECT.

You have to export the following two variables in order for GoRTR to use the proxy.
```
export HTTP_PROXY=schema://host:port
export HTTPS_PROXY=schema://host:port
```

### With SSL

You can run GoRTR and listen for TLS connections only (just pass `-bind ""`).

First, you will have to create a SSL certificate.

```bash
$ openssl ecparam -genkey -name prime256v1 -noout -outform pem > private.pem
$ openssl req -new -x509 -key private.pem -out server.pem
```

Then, you have to run

```bash
$ ./gortr -ssh.bind :8282 -tls.key private.pem -tls.cert server.pem
```

### With SSH

You can run GoRTR and listen for SSH connections only (just pass `-bind ""`).

You will have to create an ECDSA key. You can use the following command:
```bash
$ openssl ecparam -genkey -name prime256v1 -noout -outform pem > private.pem
```

Then you can start:

```bash
$ ./gortr -ssh.bind :8282 -ssh.key private.pem -bind ""
```

By default, there is no authentication.

You can use password and key authentication:

For example, to configure user **rpki** and password **rpki**:
```bash
$ ./gortr -ssh.bind :8282 -ssh.key private.pem -ssh.method.password=true -ssh.auth.user rpki -ssh.auth.password rpki -bind ""
```

And to configure a bypass for every SSH key:
```bash
$ ./gortr -ssh.bind :8282 -ssh.key private.pem -ssh.method.key=true -ssh.auth.key.bypass=true -bind ""
```

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

## Configurations

### Compatibility matrix

A simple comparison between software and devices.
Implementations on versions may vary.

| Device/software | Plaintext | TLS | SSH | Notes             |
| --------------- | --------- | --- | --- | ----------------- |
| RTRdump         | Yes       | Yes | Yes |                   |
| Juniper         | Yes       | No  | No  |                   |
| Cisco           | Yes       | No  | Yes | Only SSH password |
| Alcatel         | Yes       | No  | No  |                   |
| Arista          | No        | No  | No  |                   |
| FRRouting       | Yes       | No  | Yes | Only SSH password |
| Bird            | Yes       | No  | Yes | Only SSH key      |
| Quagga          | Yes       | No  | No  |                   |

### Configure on Juniper

Configure a session to the RTR server (assuming it runs on `192.168.1.100:8282`)

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

Show content of the database (list the PDUs)

```
louis@router> show validation database brief
RV database for instance master

Prefix                 Origin-AS Session                                 State   Mismatch
1.0.0.0/24-24              13335 192.168.1.100                           valid
1.1.1.0/24-24              13335 192.168.1.100                           valid
```

### Configure on Cisco

You may want to use the option to do SSH-based connection.

On Cisco, you can have only one RTR server per IP.

To configure a session for `192.168.1.100:8282`:
Replace `65001` by the configured ASN: 

```
router bgp 65001
 rpki server 192.168.1.100 
  transport tcp port 8282
 !
!
```

For an SSH session, you will also have to configure
`router bgp 65001 rpki server 192.168.1.100 password xxx`
where `xxx` is the password.
Some experimentations showed you have to configure
the username/password first, otherwise it will not accept the port.


```
router bgp 65001
 rpki server 192.168.1.100 
  username rpki
  transport ssh port 8282
 !
!
ssh client tcp-window-scale 14
ssh timeout 120
```

The last two SSH statements solved an issue causing the 
connection to break before receiving all the PDUs (TCP window full problem).

To visualize the state of the session:

```
RP/0/RP0/CPU0:ios#sh bgp rpki server 192.168.1.100

RPKI Cache-Server 192.168.1.100
  Transport: SSH port 8282
  Connect state: ESTAB
  Conn attempts: 1
  Total byte RX: 1726892
  Total byte TX: 452
  Last reset
    Timest: Apr 05 01:19:32 (04:26:58 ago)
    Reason: protocol error
SSH information
  Username: rpki
  Password: *****
  SSH PID: 18576
RPKI-RTR protocol information
  Serial number: 15
  Cache nonce: 0x0
  Protocol state: DATA_END
  Refresh  time: 600 seconds
  Response time: 30 seconds
  Purge time: 60 seconds
  Protocol exchange
    ROAs announced:  67358 IPv4   11754 IPv6
    ROAs withdrawn:     80 IPv4      34 IPv6
    Error Reports :      0 sent       0 rcvd
  Last protocol error
    Reason: response timeout
    Detail: response timeout while in DATA_START state
```

To visualize the accepted PDUs:

```
RP/0/RP0/CPU0:ios#sh bgp rpki table

  Network               Maxlen          Origin-AS         Server
  1.0.0.0/24            24              13335             192.168.1.100
  1.1.1.0/24            24              13335             192.168.1.100
```

## License

Licensed under the BSD 3 License.

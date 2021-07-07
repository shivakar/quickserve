# quickserve
A quick and easy file and development web server.

## Installation

To start using Quickserve, install Go and run `go get`:

```
$ go get github.com/shivakar/quickserve
```

This will install the `quickserve` command line utility into  `$GOPATH/bin`.

Make sure you have `$GOPATH/bin` added to your `$PATH` environment variable.

## Features

* Serve one or more directories
* Serve at a particular prefix
* Basic Authentication
* Serve over HTTPS (default)
* Handle (log) POST requests for quick debugging
* gzip and deflate (zlib) compression via the Accept-Encoding header

## Usage

To serve a directory using Quickserve:

```
cd <directory>
quickserve
```

Available options:

```
Usage of quickserve:
  -auth
        Enable Basic Authentication
  -certFile string
        Certificate file for TLS server.
        Implies '-tls' option.
        Also needs matching KeyFile from '-keyFile' option.
  -interface string
        Interface to serve on (default "127.0.0.1")
  -keyFile string
        Private key file for TLS server.
        Implies '-tls' option.
        Also needs matching Certificate file from '-certFile' option.
  -markdown
        Render Markdown files (default true)
  -password string
        Password for Basic Authentication (default "qspassword")
  -port string
        Port to serve on (default "8080")
  -prefix string
        Absolute path to serve on (default "/")
  -tls
        Start TLS server.
        Uses files provided with '-certFile' and '-keyFile' options
        to start the server. If no files are provided, generates an
        in-memory keypair for the server. (default true)
  -username string
        Username for Basic Authentication (default "qsuser")
  -version
        Show Version Information
```


## License

Quickserve is licensed under a MIT license.

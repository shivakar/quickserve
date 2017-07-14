package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	// Version of QuickServe
	Version string
	// Plain logger
	Plain *log.Logger
	// Info logger
	Info *log.Logger
	// Warn logger
	Warn *log.Logger
	// Error logger
	Error *log.Logger
)

// Init initalizes loggers
func Init(plainHandler io.Writer, infoHandler io.Writer,
	warnHandler io.Writer, errorHandler io.Writer) {
	Plain = log.New(plainHandler, "", 0)
	Info = log.New(infoHandler, "INFO: ",
		log.Ldate|log.Ltime)
	Warn = log.New(warnHandler, "WARN: ",
		log.Ldate|log.Ltime)
	Error = log.New(errorHandler, "Error: ",
		log.Ldate|log.Ltime)
}

// Config structure to store QuickServe state
type Config struct {
	Port      string
	Iface     string
	Dirs      []string
	BasicAuth bool
	Username  string
	Password  string
	Mux       *http.ServeMux
	Prefix    string
	TLS       bool
	CertFile  string
	KeyFile   string
	Cert      tls.Certificate
}

// Print the current config
func (c *Config) Print() {
	Info.Printf("%s\n", strings.Repeat("-", 80))
	Info.Printf("%s config:\n", os.Args[0])
	Info.Printf("\tInterface: %s\n", c.Iface)
	Info.Printf("\tPort: %s\n", c.Port)
	Info.Printf("\tPrefix: %s\n", c.Prefix)
	if len(c.Dirs) > 1 {
		Info.Printf("\tServing: %s\n", c.Dirs)
	} else {
		Info.Printf("\tServing: %s\n", c.Dirs[0])
	}
	if c.BasicAuth {
		Info.Printf("\tAuthentication: Enabled\n")
		Info.Printf("\tUsername: %s\n", c.Username)
	} else {
		Info.Printf("\tAuthentication: Disabled\n")
	}
	if c.TLS {
		Info.Printf("\tTLS: Enabled\n")
		if c.CertFile != "" && c.KeyFile != "" {
			Info.Printf("\tX509 Certificate: Provided")
			Info.Printf("\tCertificate File: %s\n", c.CertFile)
			Info.Printf("\tPrivate Key File: %s\n", c.KeyFile)
		} else {
			Info.Printf("\tx509 Certificate: Generated")
		}
	} else {
		Info.Printf("\tTLS: Disabled\n")
	}
	Info.Printf("%s\n", strings.Repeat("-", 80))
}

// LoggingMiddleware logs all requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			t := time.Now()

			u, _, ok := r.BasicAuth()
			if !ok {
				u = "-"
			}
			Info.Printf("%s - %s [%s] \"%s %s %s\"\n",
				r.RemoteAddr,
				u,
				t.Format("02/Jan/2006:15:04:05 -0700"),
				r.Method,
				r.URL.Path,
				r.Proto)

			if r.Method == "POST" {
				Info.Printf("Request HEADER:\n\t%s\n",
					r.Header)
				out, err := ioutil.ReadAll(r.Body)
				if err != nil {
					Error.Println(err)
				}
				r.ParseForm()
				Info.Printf("Request POST data:\n\t%s\n\t%s\n",
					string(out), r.Form)
			}

			next.ServeHTTP(w, r)
		})
}

// AuthenticationMiddleware adds Basic HTTP Auth
func AuthenticationMiddleware(next http.Handler, c *Config) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="quickserve"`)

			username, password, ok := r.BasicAuth()
			if !ok {
				http.Error(w, http.StatusText(http.StatusUnauthorized),
					http.StatusUnauthorized)
				return
			}
			if username != c.Username || password != c.Password {
				Error.Printf("Authorization failed for user '%s'\n", username)
				w.Header().Set("WWW-Authenticate",
					`Basic realm="quickserve - Invalid credentials. Try again."`)
				http.Error(w, http.StatusText(http.StatusUnauthorized),
					http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
}

// IndexHandler generates the index for case of multi directory server
func IndexHandler(dirs []string, prefix string) http.Handler {
	strTemplate := `
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="utf-8">
                <title>QuickServe Index</title>
            </head>
            <body>
                <ul style="list-style:none;padding:0">
                {{ range .Dirs }}
                    <li><a href="{{$.Prefix}}/{{.}}">{{.}}</a></li>
                {{ end }}
                </ul>
            </body>
        </html>
        `
	t, err := template.New("index").Parse(strTemplate)
	if err != nil {
		Error.Fatalln(err)
	}

	data := struct {
		Dirs   []string
		Prefix string
	}{
		dirs,
		prefix,
	}

	ih := func(w http.ResponseWriter, r *http.Request) {
		err = t.Execute(w, data)
		if err != nil {
			Error.Fatalln(err)
		}
	}
	return http.HandlerFunc(ih)
}

func chainMiddleware(h http.Handler, c *Config) http.Handler {
	middleware := LoggingMiddleware(h)
	if c.BasicAuth {
		middleware = AuthenticationMiddleware(middleware, c)
	}

	return middleware
}

// GenX509KeyPair generates the TLS keypair
func GenX509KeyPair() (tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:         "quickserve.example.com",
			Country:            []string{"USA"},
			Organization:       []string{"example.com"},
			OrganizationalUnit: []string{"quickserve"},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(0, 0, 1), // Valid for one day
		SubjectKeyId: []byte{113, 117, 105, 99, 107, 115, 101, 114,
			118, 101},
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return outCert, nil
}

// From https://golang.org/src/net/http/server.go
// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

// ListenAndServeTLSKeyPair start a server using in-memory TLS KeyPair
func ListenAndServeTLSKeyPair(addr string, cert tls.Certificate,
	handler http.Handler) error {

	if addr == "" {
		return errors.New("Invalid address string")
	}

	server := &http.Server{Addr: addr, Handler: handler}

	config := &tls.Config{}
	config.NextProtos = []string{"http/1.1"}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = cert

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)},
		config)

	return server.Serve(tlsListener)
}

// Serve starts the file server
func Serve(c *Config) {
	addr := c.Iface + ":" + c.Port
	if c.TLS {
		Info.Printf("Starting server at: https://%s%s\n", addr, c.Prefix)
	} else {
		Info.Printf("Starting server at: http://%s%s\n", addr, c.Prefix)
	}

	if len(c.Dirs) == 1 {
		iDir, err := filepath.Abs(c.Dirs[0])
		if err != nil {
			Error.Fatalln(err)
		}
		fileServer := http.FileServer(http.Dir(iDir))
		fileServer = http.StripPrefix(c.Prefix, fileServer)
		c.Mux.Handle(c.Prefix, chainMiddleware(fileServer, c))
	} else {
		var baseName, prefix string
		var handler http.Handler
		var iDirs []string
		for _, dir := range c.Dirs {
			iDir, err := filepath.Abs(dir)
			if err != nil {
				Error.Fatalln(err)
			}
			baseName = path.Base(iDir)
			iDirs = append(iDirs, baseName)
			prefix = fmt.Sprintf("%s/%s/", c.Prefix, baseName)
			handler = http.FileServer(http.Dir(dir))
			handler = http.StripPrefix(prefix, handler)
			c.Mux.Handle(prefix, chainMiddleware(handler, c))
		}
		indexHandler := IndexHandler(iDirs, c.Prefix)
		c.Mux.Handle(c.Prefix, chainMiddleware(indexHandler, c))
	}

	if c.TLS {
		if c.CertFile != "" && c.KeyFile != "" {
			// Start TLS server using the provided cert and key files
			Error.Fatal(http.ListenAndServeTLS(addr, c.CertFile, c.KeyFile,
				c.Mux))
		} else {
			// Start TLS server with the generated keypair
			Error.Fatal(ListenAndServeTLSKeyPair(addr, c.Cert, c.Mux))
		}
	} else {
		Error.Fatal(http.ListenAndServe(addr, c.Mux))
	}
}

func initConfig(config *Config) {
	var printVersion bool
	// Setup command line flags
	flag.StringVar(&config.Port, "port", "8080", "Port to serve on")
	flag.StringVar(&config.Iface, "interface", "127.0.0.1",
		"Interface to serve on")
	flag.BoolVar(&config.BasicAuth, "auth", false,
		"Enable Basic Authentication")
	flag.StringVar(&config.Username, "username", "qsuser",
		"Username for Basic Authentication")
	flag.StringVar(&config.Password, "password", "qspassword",
		"Password for Basic Authentication")
	flag.StringVar(&config.Prefix, "prefix", "/", "Absolute path to serve on")
	flag.BoolVar(&config.TLS, "tls", true,
		"Start TLS server.\n"+
			"\tUses files provided with '-certFile' and '-keyFile' options\n"+
			"\tto start the server. If no files are provided, generates an\n"+
			"\tin-memory keypair for the server.")
	flag.StringVar(&config.CertFile, "certFile", "",
		"Certificate file for TLS server.\n\tImplies '-tls' option.\n"+
			"\tAlso needs matching KeyFile from '-keyFile' option.")
	flag.StringVar(&config.KeyFile, "keyFile", "",
		"Private key file for TLS server.\n\tImplies '-tls' option.\n"+
			"\tAlso needs matching Certificate file from '-certFile' option.")
	flag.BoolVar(&printVersion, "version", false, "Show Version Information")

	// Parse command line flags
	flag.Parse()

	// Handle version request
	if printVersion {
		Plain.Printf("%s %s\n", os.Args[0], Version)
		flag.Usage()
		os.Exit(0)
	}

	// Clean Prefix and format the prefix
	config.Prefix = path.Clean(fmt.Sprintf("/%s", config.Prefix))

	// Setup directory to serve
	var err error
	if flag.NArg() < 1 {
		iDir, err := os.Getwd()
		if err != nil {
			Error.Fatalln(err)
		}
		config.Dirs = []string{iDir}
	} else {
		config.Dirs = flag.Args()
	}

	// Check if the directories to serve actually exist
	for _, dir := range config.Dirs {
		_, err = os.Stat(dir)
		if err != nil {
			Error.Fatalln(err)
		}
	}

	// Check TLS configuration
	if config.CertFile != "" || config.KeyFile != "" {
		if config.CertFile == "" || config.KeyFile == "" {
			Error.Fatalln("Both certFile and keyFile options must be provided.")
		}
		// Check if the files actually exist
		if _, err = os.Stat(config.CertFile); err != nil {
			Error.Fatalln(err)
		}
		if _, err = os.Stat(config.KeyFile); err != nil {
			Error.Fatalln(err)
		}
		config.TLS = true
	} else if config.TLS {
		if config.Cert, err = GenX509KeyPair(); err != nil {
			Error.Fatalln(err)
		}
	}

	config.Mux = http.NewServeMux()
}

func main() {
	Version = "0.2.0"
	Init(os.Stdout, os.Stdout, os.Stdout, os.Stderr)

	// Create new config
	config := new(Config)

	// Parse Command line arguments and initialize config
	initConfig(config)

	// Done with configuration
	config.Print()

	// Use all available CPU cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	Serve(config)
}

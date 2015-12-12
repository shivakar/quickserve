package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
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
	Info.Printf("%s\n", strings.Repeat("-", 80))
}

// LoggingMiddleware logs all requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			t := time.Now()

			Info.Printf("%s - - [%s] \"%s %s %s\"\n",
				r.RemoteAddr,
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
			authHdr := r.Header["Authorization"]
			if len(authHdr) > 0 {
				authInfo := strings.Split(authHdr[0], " ")
				if len(authInfo) != 2 || authInfo[0] != "Basic" {
					Error.Printf("Invalid Auth Syntax: %s\n", authHdr)
					http.Error(w, "Invalid Auth Syntax", http.StatusBadRequest)
					return
				}
				credentials, err := base64.StdEncoding.DecodeString(authInfo[1])
				if err != nil {
					Error.Printf("Invalid Auth Data: %s\n", authInfo[1])
					http.Error(w, "Invalid Auth Data", http.StatusBadRequest)
					return
				}
				creds := strings.Split(string(credentials), ":")
				if len(creds) != 2 || creds[0] != c.Username ||
					creds[1] != c.Password {
					Error.Printf("Authorization failed for user '%s'\n",
						creds[0])
					http.Error(w, "Authorization failed",
						http.StatusUnauthorized)
					return
				}
			} else {
				w.Header().Set("WWW-Authenticate",
					"Basic realm=\"quickserve\"")
				http.Error(w, http.StatusText(401), 401)
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

// Serve starts the file server
func Serve(c *Config) {
	addr := c.Iface + ":" + c.Port
	Info.Printf("Starting server at: http://%s%s/\n", addr, c.Prefix)

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

	Error.Fatal(http.ListenAndServe(addr, c.Mux))
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

	config.Mux = http.NewServeMux()
}

func main() {
	Version = "0.1.0"
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

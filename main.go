package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"shortlink/helpers"
	"strings"
	"time"

	"github.com/ravener/discord-oauth2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"github.com/go-co-op/gocron"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var (
	oauthConfig *oauth2.Config
	store       = sessions.NewCookieStore([]byte("secret"))
)

func initOauth(config helpers.Configuration) {
	store = sessions.NewCookieStore([]byte(config.OAuth.Secret))
	if config.OAuth.Type == "discord" {
		oauthConfig = &oauth2.Config{
			ClientID:     config.OAuth.ClientID,
			ClientSecret: config.OAuth.ClientSecret,
			RedirectURL:  config.OAuth.RedirectURL,
			Scopes:       []string{discord.ScopeIdentify},
			Endpoint:     discord.Endpoint,
		}
	} else if config.OAuth.Type == "google" {
		oauthConfig = &oauth2.Config{
			ClientID:     config.OAuth.ClientID,
			ClientSecret: config.OAuth.ClientSecret,
			RedirectURL:  config.OAuth.RedirectURL,
			Scopes:       []string{"profile", "email"},
			Endpoint:     google.Endpoint,
		}
	} else if config.OAuth.Type == "github" {
		oauthConfig = &oauth2.Config{
			ClientID:     config.OAuth.ClientID,
			ClientSecret: config.OAuth.ClientSecret,
			RedirectURL:  config.OAuth.RedirectURL,
			Scopes:       []string{"user:email", "read:user"},
			Endpoint:     github.Endpoint,
		}
	}
}

var rootServe string

var db *sql.DB

func addToCache(id string, data []byte) {
	fileCache[id] = data
}

func getFromCache(id string) []byte {
	if data, ok := fileCache[id]; ok {
		return data
	}
	return nil
}

var templates *template.Template

func handleRequests(config helpers.Configuration) {
	// we parse all templates in templates/
	templates = template.Must(template.ParseGlob("templates/*.tmpl"))

	router := mux.NewRouter().StrictSlash(true)
	// link-shortening listeners
	if config.Webserver.RootServe != "" {
		rootServe = config.Webserver.RootServe
		router.HandleFunc("/", homePage)
	}
	router.HandleFunc("/admin", authMiddleware(adminPage)).Methods("GET")
	router.HandleFunc("/admin/remove/{term}", authMiddleware(adminPageRemove))
	router.HandleFunc("/admin/add", authMiddleware(adminPageAdd))
	router.HandleFunc("/admin/add/{short}/{long}", authMiddleware(adminPageAddShort))

	router.HandleFunc("/admin/login", loginHandler).Methods("GET")
	router.HandleFunc("/admin/logout", logoutHandler).Methods("GET")
	router.HandleFunc("/admin/callback", callbackHandler).Methods("GET")

	// we have to handle /admin/main.css
	router.PathPrefix("/admin/main.css").Handler(http.StripPrefix("/admin/", http.FileServer(http.Dir("admin/"))))
	router.HandleFunc("/{id}", shortenLink)

	router.NotFoundHandler = http.HandlerFunc(notFoundHandler)

	server := http.Server{
		Addr:    ":8081",
		Handler: router,
		TLSConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
		},
	}

	fmt.Printf("Server listening on %s\n", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		fmt.Println(err)
	}
}

var fileCache = make(map[string][]byte)

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		_, ok := session.Values["authenticated"]

		if !ok {
			// http.Error(w, "Unauthorized", http.StatusUnauthorized)
			// get current timestamp
			t := time.Now()
			data := helpers.PageData{
				PageTitle: "Shorty - Unauthorized",
				Footer:    "© 2023 ptgms Industries - Page loaded in " + fmt.Sprintf("%d", time.Since(t).Milliseconds()) + "ms",
			}

			err := templates.ExecuteTemplate(w, "unauth", data)
			helpers.HandleError(err, false)

			return
		}

		next(w, r)
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	//	print url to writer
	_, err := fmt.Fprintf(w, "404 - Not Found - %s", r.URL.Path)
	helpers.HandleError(err, false)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["state"] = "random-state"
	err := session.Save(r, w)
	helpers.HandleError(err, false)

	url := oauthConfig.AuthCodeURL(session.Values["state"].(string))

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	delete(session.Values, "authenticated")
	err := session.Save(r, w)
	helpers.HandleError(err, false)

	t := time.Now()
	data := helpers.PageData{
		PageTitle: "Shorty - Logged out",
		Footer:    "© 2023 ptgms Industries - Page loaded in " + fmt.Sprintf("%d", time.Since(t).Milliseconds()) + "ms",
	}

	err = templates.ExecuteTemplate(w, "loggedout", data)
	helpers.HandleError(err, false)

	//http.Redirect(w, r, "/", http.StatusSeeOther)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	queryState := r.URL.Query().Get("state")
	if queryState != session.Values["state"].(string) {
		http.Error(w, "Invalid callback state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Check if token is valid
	valid, authUser := helpers.IsTokenValid(token, config, oauthConfig)
	if !valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// check if config.PermittedUsers contains authUser.ID
	if !helpers.IsIDPermitted(authUser.ID, config.PermittedUsers) {
		http.Error(w, "User not permitted. Ask Owner to permit ID "+authUser.ID, http.StatusUnauthorized)
		return
	}

	// Set username in session
	session.Values["username"] = authUser.Username

	// Set authenticated flag in session
	session.Values["authenticated"] = true
	err = session.Save(r, w)
	helpers.HandleError(err, false)

	// Set a cookie to remember login for 1 week
	cookie := http.Cookie{
		Name:     "auth_token",
		Value:    token.AccessToken,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func homePage(w http.ResponseWriter, _ *http.Request) {
	// check if we have the file in cache
	if data := getFromCache("rootserve"); data != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := w.Write(data)
		helpers.HandleError(err, false)
		return
	}

	file, err := os.Open(rootServe)
	helpers.HandleError(err, false)
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			helpers.HandleError(err, false)
		}
	}(file)

	var buf bytes.Buffer
	_, err = io.Copy(&buf, file)
	helpers.HandleError(err, false)

	content := buf.Bytes()
	addToCache("rootserve", content)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = w.Write(content)
	helpers.HandleError(err, false)
}

func adminPageRemove(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	term := vars["term"]

	termsSplit := strings.Split(term, ",")

	for _, term := range termsSplit {
		helpers.RemoveLink(db, term)
	}

	http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
}

func adminPageAddShort(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	short := vars["short"]
	long := strings.Replace(vars["long"], ".", "/", -1)
	expires := r.URL.Query().Get("expires")

	long = helpers.Base64Decode(long)
	short = helpers.Base64Decode(short)

	helpers.AddLink(db, long, short, expires)
	http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
}

func adminPage(w http.ResponseWriter, r *http.Request) {
	// get current timestamp
	t := time.Now()
	//  get user from session
	session, _ := store.Get(r, "session-name")
	username := session.Values["username"]
	data := helpers.PageData{
		PageTitle: "Shorty Admin",
		LoginName: username.(string),
		Links:     helpers.GetLinks(db, config.Webserver.Domain),
		Footer:    "© 2023 ptgms Industries - Page loaded in " + fmt.Sprintf("%d", time.Since(t).Milliseconds()) + "ms",
	}

	err := templates.ExecuteTemplate(w, "admin", data)
	helpers.HandleError(err, false)
}

func adminPageAdd(w http.ResponseWriter, r *http.Request) {
	// get current timestamp
	t := time.Now()
	//  get user from session
	session, _ := store.Get(r, "session-name")
	username := session.Values["username"]
	data := helpers.PageData{
		PageTitle: "Shorty Admin",
		LoginName: username.(string),
		Footer:    "© - Page loaded in " + fmt.Sprintf("%d", time.Since(t).Milliseconds()) + "ms",
	}

	err := templates.ExecuteTemplate(w, "adminadd", data)
	helpers.HandleError(err, false)
}

func shortenLink(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["id"]
	if key == "" || key == "admin" || key == "favicon.ico" {
		return
	}

	// check if we have the url in cache
	if data := getFromCache(key); data != nil {
		// redirect to the link
		http.Redirect(w, r, string(data), http.StatusMovedPermanently)
		return
	}

	// get the link from the database
	var link = helpers.GetLink(db, key)

	// redirect to the link
	http.Redirect(w, r, link, http.StatusMovedPermanently)

	if link == "" {
		return
	}

	// add the link to cache
	addToCache(key, []byte(link))

	// increase the counter
	helpers.RegisterClick(db, key)
}

func task() {
	fmt.Println("Task running")
	// let's invalidate the cache
	fileCache = make(map[string][]byte)
}

func prepareScheduler() {
	s := gocron.NewScheduler(time.UTC)
	_, err := s.Every(24).Hours().Do(task)
	if err != nil {
		return
	}
	if err != nil {
		println(err.Error())
		return
	}
	// Start the scheduler in a thread
	s.StartAsync()
}

var config helpers.Configuration

func main() {
	if helpers.DoesFileExist("config.json") {
		config = helpers.LoadConfig()
		if config.Webserver.RootServe != "" {
			if !helpers.DoesFileExist(config.Webserver.RootServe) {
				fmt.Println("RootServe file does not exist. Please check config.json / create the file.")
				os.Exit(1)
			}
		}
	} else {
		helpers.SaveEmptyConfig()
		fmt.Println("Please edit config.json and restart the server.")
		os.Exit(1)
	}

	db = helpers.CreateConnection(config)
	initOauth(config)
	prepareScheduler()
	handleRequests(config)
}

package router

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/muhhae/learn-oauth/authenticator"
	"github.com/muhhae/learn-oauth/middleware"
	"github.com/muhhae/learn-oauth/view"
)

func New(auth *authenticator.Authenticator) *echo.Echo {
	router := echo.New()

	gob.Register(map[string]interface{}{})

	storeSecret := os.Getenv("STORE_SECRET")
	if storeSecret == "" {
		log.Fatalln("ENV STORE_SECRET NOT SET")
	}
	store := sessions.NewCookieStore([]byte(
		os.Getenv("STORE_SECRET"),
	))
	router.Use(session.Middleware(store))
	router.GET("/", func(c echo.Context) error {
		return c.HTML(http.StatusOK, view.Home())
	})

	router.GET("/login", loginHandler(auth))
	router.GET("/callback", callbackHandler(auth))
	router.GET("/user", userHandler(auth), middleware.IsAuthenticated)
	router.GET("/logout", logoutHandler(auth))

	router.GET("/profile-delete", func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		sess.Values["profile"] = nil
		sess.Save(c.Request(), c.Response())
		return c.Redirect(http.StatusTemporaryRedirect, "/login")
	})

	return router
}

func loginHandler(auth *authenticator.Authenticator) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		state, err := generateRandomState()
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		sess.Values["state"] = state
		if err := sess.Save(c.Request(), c.Response()); err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.Redirect(http.StatusTemporaryRedirect, auth.AuthCodeURL(state))
	}
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	state := base64.StdEncoding.EncodeToString(b)
	return state, nil
}

func callbackHandler(auth *authenticator.Authenticator) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		if c.QueryParam("state") != sess.Values["state"] {
			return c.String(http.StatusBadRequest, "Invalid state parameter")
		}
		token, err := auth.Exchange(c.Request().Context(), c.QueryParam("code"))
		if err != nil {
			return c.String(http.StatusUnauthorized, "Failed to exchange authorization code for a token")
		}
		idToken, err := auth.VerifyIDToken(c.Request().Context(), token)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to verify ID Token")
		}
		var profile map[string]interface{}
		if err := idToken.Claims(&profile); err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		sess.Values["access_token"] = token.AccessToken
		sess.Values["profile"] = profile
		sess.Options.MaxAge = 60 * 60 * 2
		if err := sess.Save(c.Request(), c.Response()); err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.Redirect(http.StatusTemporaryRedirect, "/user")
	}
}

func userHandler(auth *authenticator.Authenticator) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		sessionProfile := sess.Values["profile"]
		if sessionProfile == nil {
			return c.String(http.StatusInternalServerError, "No profile found in current session")
		}
		profile := sessionProfile.(map[string]interface{})
		for i := range profile {
			log.Println(i, ":", profile[i])
		}
		return c.HTML(http.StatusOK, view.UserProfile(view.ProfileData{
			Picture:  profile["picture"].(string),
			Nickname: profile["name"].(string),
		}))
	}
}

func logoutHandler(auth *authenticator.Authenticator) echo.HandlerFunc {
	return func(c echo.Context) error {
		logourUrl, err := url.Parse("https://" + os.Getenv("OAUTH_DOMAIN") + "/v2/logout")
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		scheme := "http"
		if c.Request().TLS != nil {
			scheme = "https"
		}

		returnTo, err := url.Parse(scheme + "://" + c.Request().Host)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}

		param := url.Values{}
		param.Add("returnTo", returnTo.String())
		param.Add("client_id", os.Getenv("OAUTH_CLIENT"))
		logourUrl.RawQuery = param.Encode()

		sess, err := session.Get("session", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		sess.Options = &sessions.Options{
			Path:   "/",
			MaxAge: -1,
		}
		sess.Save(c.Request(), c.Response())
		return c.Redirect(http.StatusTemporaryRedirect, logourUrl.String())
	}
}

package router

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
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
	"golang.org/x/oauth2"
)

func New(a *authenticator.Authenticator) *echo.Echo {
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

	router.GET("/login", loginHandler(a))
	router.GET("/callback", callbackHandler(a))
	router.GET("/user", userHandler(a), middleware.IsAuthenticated)
	router.GET("/logout", logoutHandler(a))

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
		loginUrl := auth.AuthCodeURL(state)

		if c.QueryParam("silent") == "true" {
			loginUrl = auth.AuthCodeURL(
				state,
				oauth2.SetAuthURLParam("response_type", "code"),
				oauth2.SetAuthURLParam("prompt", "none"),
			)
		}

		fmt.Println(loginUrl)
		return c.Redirect(http.StatusTemporaryRedirect, loginUrl)
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
		if c.QueryParam("error") != "" {
			return c.Redirect(http.StatusTemporaryRedirect, "/login")
		}
		fmt.Println("QueryParam state", c.QueryParam("state"))
		fmt.Println("Session state", sess.Values["state"])
		if c.QueryParam("state") != sess.Values["state"].(string) {
			return c.String(http.StatusBadRequest, "Invalid state parameter ")
		}
		token, err := auth.Exchange(c.Request().Context(), c.QueryParam("code"), oauth2.AccessTypeOffline)
		if err != nil {
			return c.String(http.StatusUnauthorized, "Failed to exchange authorization code for a token")
		}

		sess.Values["refresh_token"] = token.RefreshToken
		sess.Values["access_token"] = token.AccessToken
		sess.Values["id_token"] = token.Extra("id_token")
		if err := sess.Save(c.Request(), c.Response()); err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}

		return c.Redirect(http.StatusTemporaryRedirect, "/user")
	}
}

func userHandler(a *authenticator.Authenticator) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		idToken := sess.Values["id_token"].(string)
		oidToken, err := a.VerifyIDToken(c.Request().Context(), idToken)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		var profile map[string]interface{}
		err = oidToken.Claims(&profile)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}

		profile["access_token"] = sess.Values["access_token"]
		profile["refresh_token"] = sess.Values["refresh_token"]
		return c.JSON(http.StatusOK, profile)
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

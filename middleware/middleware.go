package middleware

import (
	"net/http"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func IsAuthenticated(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session", c)
		if err != nil || sess.Values["access_token"] == nil {
			return c.Redirect(http.StatusTemporaryRedirect, "/login")
		}
		return next(c)
	}
}

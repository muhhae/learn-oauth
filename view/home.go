package view

import (
	"github.com/muhhae/webstruct/element"
	"github.com/muhhae/webstruct/webtype"
)

func Home() string {
	return element.Div{
		Children: webtype.Children{
			element.H3{
				Children: webtype.Children{
					element.RawText("Auth0 Example"),
				},
			},
			element.P{
				Children: webtype.Children{
					element.RawText("Zero friction identity infrastructure, build for developers"),
				},
			},
			element.A{
				Href: "/login",
				Children: webtype.Children{
					element.RawText("Login"),
				},
			},
			element.A{
				Href: "/login?silent=true",
				Children: webtype.Children{
					element.RawText("Silent Login"),
				},
			},
			element.A{
				Href: "/logout",
				Children: []webtype.HtmlElement{
					element.RawText("Logout"),
				},
			},
			element.A{
				Href: "/user",
				Children: webtype.Children{
					element.RawText("Profile"),
				},
			},
		},
	}.Html()
}

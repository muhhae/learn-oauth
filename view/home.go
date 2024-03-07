package view

import (
	"github.com/muhhae/webstruct/element"
	"github.com/muhhae/webstruct/webtype"
)

func Home() string {
	return element.Div{
		Children: []webtype.HtmlElement{
			element.CustomElement{
				Tag: "h3",
				Children: []webtype.HtmlElement{
					element.RawText("Auth0 Example"),
				},
			},
			element.CustomElement{
				Tag: "p",
				Children: []webtype.HtmlElement{
					element.RawText("Zero friction identity infrastructure, build for developers"),
				},
			},
			element.CustomElement{
				Tag: "a",
				Attributes: webtype.Attribute{
					"href": "/login",
				},
				Children: []webtype.HtmlElement{
					element.RawText("Sign In"),
				},
			},
			element.CustomElement{
				Tag: "a",
				Attributes: webtype.Attribute{
					"href": "/user",
				},
				Children: []webtype.HtmlElement{
					element.RawText("Profile"),
				},
			},
			element.CustomElement{
				Tag: "a",
				Attributes: webtype.Attribute{
					"href": "/profile-delete",
				},
				Children: []webtype.HtmlElement{
					element.RawText("Profile Delete"),
				},
			},
		},
	}.Html()
}

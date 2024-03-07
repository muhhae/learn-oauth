package view

import (
	"github.com/muhhae/webstruct/element"
	"github.com/muhhae/webstruct/webtype"
)

type ProfileData struct {
	Picture  string
	Nickname string
}

func UserProfile(profileData ProfileData) string {
	return element.Div{
		Children: []webtype.HtmlElement{
			element.CustomElement{
				Tag: "img",
				Attributes: webtype.Attribute{
					"src": profileData.Picture,
				},
			},
			element.CustomElement{
				Tag: "h2",
				Children: []webtype.HtmlElement{
					element.RawText("Welcome " + profileData.Nickname),
				},
			},
			element.CustomElement{
				Tag: "a",
				Children: []webtype.HtmlElement{
					element.RawText("Log Out"),
				},
				Attributes: webtype.Attribute{
					"href": "/logout",
				},
			},
		},
	}.Html()
}

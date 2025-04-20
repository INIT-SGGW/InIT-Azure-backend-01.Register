package model

import "html/template"

type UserVerificationEmailTemplateModel struct {
	Sender            string
	Recipients        []string
	VerificationToken string
	VerificationLink  template.URL
}

package model

type UserVerificationEmailTemplateModel struct {
	Sender            string
	Recipients        []string
	VerificationToken string
}

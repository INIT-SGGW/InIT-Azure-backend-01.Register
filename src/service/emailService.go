package service

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/model"
	"INIT-SGGW/InIT-Azure-backend-01.Register/repository"
	"bytes"
	"context"
	"fmt"
	"html/template"
	"strconv"

	"go.uber.org/zap"
	gomail "gopkg.in/mail.v2"
)

type EmailService struct {
	service     *Service
	user        string
	password    string
	emailHost   string
	emailPort   string
	emailSender string
	repository  repository.EmailRepository
}

type EmailTemplateService interface {
	SendUserVerificationEmail(ctx context.Context, user model.User) error
}

func NewEmailService(logger *zap.Logger, user, password, emailHost, emailPort, emailSender string, repository repository.EmailRepository) *EmailService {
	return &EmailService{
		service:     NewService(logger),
		user:        user,
		password:    password,
		emailHost:   emailHost,
		emailPort:   emailPort,
		emailSender: emailSender,
		repository:  repository,
	}
}

func (srv EmailService) SendUserVerificationEmail(ctx context.Context, user model.User) error {
	defer srv.service.logger.Sync()
	templateName := "icc_account_verification"

	emailTmpl, err := srv.repository.GetSingleTemplateByName(templateName, ctx)
	if err != nil {
		srv.service.logger.Error("Cannot retreive email template",
			zap.String("templateName", templateName),
			zap.Error(err))
		return err
	}
	templUser := model.UserVerificationEmailTemplateModel{
		Sender:            srv.emailSender,
		VerificationToken: user.VerificationToken,
		Recipients:        user.Emails,
	}

	email, err := srv.fillTemplate(emailTmpl, templUser)
	if err != nil {
		srv.service.logger.Error("Error parsing template",
			zap.String("templateName", emailTmpl.TemplateName),
			zap.Error(err))
		return err
	}

	port, _ := strconv.Atoi(srv.emailPort)
	dialer := gomail.NewDialer(srv.emailHost, port, srv.user, srv.password)

	err = dialer.DialAndSend(email)
	if err != nil {
		srv.service.logger.Error("Error sending email",
			zap.String("templateName", emailTmpl.TemplateName),
			zap.String("host", srv.emailHost),
			zap.Error(err))
		return err
	}

	srv.service.logger.Info("Succesfully sending email",
		zap.Strings("emails", user.Emails),
		zap.String("templateName", emailTmpl.TemplateName),
		zap.String("host", srv.emailHost))

	return err
}

func (srv EmailService) fillTemplate(emailTmpl model.EmailTemplate, templModel model.UserVerificationEmailTemplateModel) (*gomail.Message, error) {
	defer srv.service.logger.Sync()
	message := gomail.NewMessage()

	htmlTmplName := fmt.Sprintf("%s_html", emailTmpl.TemplateName)
	htmlTemplate, err := template.New(htmlTmplName).Parse(emailTmpl.TemplateHtmlBody)
	if err != nil {
		srv.service.logger.Error("Error parsing template headers",
			zap.String("templateName", htmlTmplName),
			zap.Error(err))
		return &gomail.Message{}, err
	}

	buf := &bytes.Buffer{}
	err = htmlTemplate.Execute(buf, templModel)
	if err != nil {
		srv.service.logger.Error("Error executing html template",
			zap.String("templateName", htmlTmplName),
			zap.Error(err))
		return &gomail.Message{}, err
	}

	message.SetHeader("From", templModel.Sender)
	message.SetHeader("To", templModel.Recipients...)
	message.SetHeader("Subject", emailTmpl.Subject)
	message.SetBody("text/html", buf.String())

	textTmplName := fmt.Sprintf("%s_text", emailTmpl.TemplateName)
	textTemplate, err := template.New(textTmplName).Parse(emailTmpl.TemplateAlternateBody)
	if err != nil {
		srv.service.logger.Error("Error parsing template headers",
			zap.String("templateName", htmlTmplName),
			zap.Error(err))
		return &gomail.Message{}, err
	}

	buf = &bytes.Buffer{}
	err = textTemplate.Execute(buf, templModel)
	if err != nil {
		srv.service.logger.Error("Error executing text template",
			zap.String("templateName", textTmplName),
			zap.Error(err))
		return &gomail.Message{}, err
	}

	message.AddAlternative("text/plain", buf.String())

	return message, err

}

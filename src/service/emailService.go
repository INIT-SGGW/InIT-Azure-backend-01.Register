package service

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/model"
	"INIT-SGGW/InIT-Azure-backend-01.Register/repository"
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"strconv"
	textTemplate "text/template"

	"go.mongodb.org/mongo-driver/mongo"

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
	ICCDomain   string
	HADomain    string
}

type EmailTemplateService interface {
	SendUserVerificationEmail(ctx context.Context, service string, user model.User) error
	SendEmailVerificationEmail(ctx context.Context, user model.User, email string) error
	SendAdminVerificationEmail(ctx context.Context, admin model.Admin) error
	ResendVerificationEmail(ctx context.Context, service string, email string) error
	SendCreateUserEmail(ctx context.Context, user model.User) error
}

func NewEmailService(logger *zap.Logger, user, password, emailHost, emailPort, emailSender, ICCDomain, HADomain string, repository repository.EmailRepository) *EmailService {
	return &EmailService{
		service:     NewService(logger),
		user:        user,
		password:    password,
		emailHost:   emailHost,
		emailPort:   emailPort,
		emailSender: emailSender,
		repository:  repository,
		ICCDomain:   ICCDomain,
		HADomain:    HADomain,
	}
}

func (srv EmailService) SendUserVerificationEmail(ctx context.Context, service string, user model.User) error {
	defer srv.service.logger.Sync()

	var emailConfigs = map[string]struct {
		Domain        string
		VerifyURLPath string
		TemplateName  string
	}{
		"icc": {
			Domain:        srv.ICCDomain,
			VerifyURLPath: "/register/email/verification",
			TemplateName:  "icc_account_verification",
		},
		"ha": {
			Domain:        srv.HADomain,
			VerifyURLPath: "/rejestracja/email/weryfikacja",
			TemplateName:  "ha_account_verification",
		},
	}

	config, ok := emailConfigs[service]
	if !ok {
		srv.service.logger.Error("Service not supported",
			zap.String("service", service))
		return errors.New("service not supported")
	}

	templateName := config.TemplateName

	emailTmpl, err := srv.repository.GetSingleTemplateByName(templateName, ctx)
	if err != nil {
		srv.service.logger.Error("Cannot retreive email template",
			zap.String("templateName", templateName),
			zap.Error(err))
		return err
	}
	linkUrl, err := url.Parse(config.Domain)
	if err != nil {
		srv.service.logger.Error("Error creating verification link",
			zap.String("templateName", templateName),
			zap.Error(err))
		return err
	}
	linkUrl.Path += config.VerifyURLPath
	params := url.Values{}
	for _, email := range user.Emails {
		params.Add("email", email)
	}
	params.Add("token", user.VerificationToken)
	linkUrl.RawQuery += params.Encode()

	link := linkUrl.String()
	templUser := model.UserVerificationEmailTemplateModel{
		Sender:            srv.emailSender,
		VerificationToken: user.VerificationToken,
		Recipients:        user.Emails,
		VerificationLink:  template.URL(link),
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

func (srv EmailService) SendCreateUserEmail(ctx context.Context, user model.User) error {
	defer srv.service.logger.Sync()

	templateName := "ha_create_user"

	emailTmpl, err := srv.repository.GetSingleTemplateByName(templateName, ctx)
	if err != nil {
		srv.service.logger.Error("Cannot retreive email template",
			zap.String("templateName", templateName),
			zap.Error(err))
		return err
	}
	linkUrl, err := url.Parse(srv.HADomain)
	if err != nil {
		srv.service.logger.Error("Error creating verification link",
			zap.String("templateName", templateName),
			zap.Error(err))
		return err
	}
	linkUrl.Path += "/rejestracja/uzytkownik/zaproszenie"
	params := url.Values{}
	for _, email := range user.Emails {
		params.Add("email", email)
	}
	params.Add("token", user.VerificationToken)
	linkUrl.RawQuery += params.Encode()

	link := linkUrl.String()
	templUser := model.UserVerificationEmailTemplateModel{
		Sender:            srv.emailSender,
		VerificationToken: user.VerificationToken,
		Recipients:        user.Emails,
		VerificationLink:  template.URL(link),
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

func (srv EmailService) SendEmailVerificationEmail(ctx context.Context, user model.User, email string) error {
	defer srv.service.logger.Sync()

	templateName := "init_add_email_verification"

	emailTmpl, err := srv.repository.GetSingleTemplateByName(templateName, ctx)
	if err != nil {
		srv.service.logger.Error("Cannot retreive email template",
			zap.String("templateName", templateName),
			zap.Error(err))
		return err
	}
	linkUrl, err := url.Parse(srv.ICCDomain)
	if err != nil {
		srv.service.logger.Error("Error creating verification link",
			zap.String("templateName", templateName),
			zap.Error(err))
		return err
	}
	linkUrl.Path += "/register/add/email/verification"
	params := url.Values{}
	params.Add("email", email)
	params.Add("token", user.VerificationToken)
	linkUrl.RawQuery += params.Encode()

	emailList := []string{email}

	link := linkUrl.String()
	templUser := model.UserVerificationEmailTemplateModel{
		Sender:            srv.emailSender,
		VerificationToken: user.VerificationToken,
		Recipients:        emailList,
		VerificationLink:  template.URL(link),
	}

	message, err := srv.fillTemplate(emailTmpl, templUser)
	if err != nil {
		srv.service.logger.Error("Error parsing template",
			zap.String("templateName", emailTmpl.TemplateName),
			zap.Error(err))
		return err
	}

	port, _ := strconv.Atoi(srv.emailPort)
	dialer := gomail.NewDialer(srv.emailHost, port, srv.user, srv.password)

	err = dialer.DialAndSend(message)
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

func (srv EmailService) ResendVerificationEmail(ctx context.Context, service string, email string) error {
	defer srv.service.logger.Sync()

	srv.service.logger.Debug("In method ResendVerificationEmail")

	userDbo, err := srv.repository.GetUserByEmail(ctx, email)
	if err == mongo.ErrNoDocuments {
		srv.service.logger.Error("The user email is not in the database",
			zap.String("email", email),
			zap.Error(err))

		return err
	}
	if err != nil {
		srv.service.logger.Error("Error in retreiving user from database",
			zap.String("email", email),
			zap.Error(err))

		return err
	}

	srv.service.logger.Info("Sucesfully retreive the user form database",
		zap.String("email", userDbo.Emails[0]),
		zap.String("userId", userDbo.ID.String()))

	err = srv.SendUserVerificationEmail(ctx, service, userDbo)
	if err != nil {
		srv.service.logger.Error("Error sending email",
			zap.String("email", email),
			zap.String("host", srv.emailHost),
			zap.Error(err))
		return err
	}

	srv.service.logger.Info("Sucesfully resend  user verification email",
		zap.String("email", userDbo.Emails[0]),
		zap.String("userId", userDbo.ID.String()))

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
	textTemplate, err := textTemplate.New(textTmplName).Parse(emailTmpl.TemplateAlternateBody)
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

func (srv EmailService) SendAdminVerificationEmail(ctx context.Context, admin model.Admin) error {
	defer srv.service.logger.Sync()

	templateName := "admin_verification"

	emailTmpl, err := srv.repository.GetSingleTemplateByName(templateName, ctx)
	if err != nil {
		srv.service.logger.Error("Cannot retreive email template",
			zap.String("templateName", templateName),
			zap.Error(err))
		return err
	}
	linkUrl, err := url.Parse(srv.ICCDomain)
	if err != nil {
		srv.service.logger.Error("Error creating verification link",
			zap.String("templateName", templateName),
			zap.Error(err))
		return err
	}
	linkUrl.Path += "/admin/admin/verification"
	params := url.Values{}

	params.Add("email", admin.Email)

	params.Add("token", admin.VerificationToken)
	linkUrl.RawQuery += params.Encode()

	// we can use the same template as for user verification
	link := linkUrl.String()
	templUser := model.UserVerificationEmailTemplateModel{
		Sender:            srv.emailSender,
		VerificationToken: admin.VerificationToken,
		Recipients:        []string{admin.Email},
		VerificationLink:  template.URL(link),
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
		zap.String("email", admin.Email),
		zap.String("templateName", emailTmpl.TemplateName),
		zap.String("host", srv.emailHost))

	return err

}

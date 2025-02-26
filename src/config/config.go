package config

import (
	"errors"
	"fmt"
	"os"
)

type envConfig struct {
	Env                  string
	DbConnStr            string
	DbName               string
	LogPath              string
	ListenPort           string
	SmtpPass             string
	SmtpUser             string
	SmtpPort             string
	SmtpHost             string
	SmtpSenderEmail      string
	VerificationLinkHost string
}

func NewEnvConfig() envConfig {
	var err error
	env, exist := os.LookupEnv("INIT_ENV")
	if !exist {
		err = errors.Join(err, errors.New("Missing environment variable INIT_ENV"))
	}

	logPath, exist := os.LookupEnv("KN_INIT_LOG_PATH")
	if !exist {
		fmt.Println("Log path is not set in env variable KN_INIT_LOG_PATH")
		fmt.Println("All logs will be redirected to stdout")
		logPath = " "
	}
	connString, exist := os.LookupEnv("INIT_DB_CONN_STR")
	if !exist {
		err = errors.Join(err, errors.New("Missing environment variable INIT_DB_CONN_STR"))

	}

	dbname, exist := os.LookupEnv("INIT_MONGO_DB_NAME")
	if !exist {
		err = errors.Join(err, errors.New("Missing environment variable INIT_MONGO_DB_NAME "))
	}

	listenPort, exist := os.LookupEnv("INIT_LISTEN_PORT")
	if !exist {
		fmt.Println("Setting listen port to default 3131")
		listenPort = "3131"
	}

	smtpPass, exist := os.LookupEnv("INIT_SMTP_PWD")
	if !exist {
		err = errors.Join(err, errors.New("Missing environment variable INIT_SMTP_PWD"))

	}

	SmtpUser, exist := os.LookupEnv("INIT_SMTP_USR")
	if !exist {
		err = errors.Join(err, errors.New("Missing environment variable INIT_SMTP_USR"))

	}
	SmtpPort, exist := os.LookupEnv("INIT_SMTP_PORT")
	if !exist {
		fmt.Println("SMTP port is not set in env variable INIT_SMTP_PORT")
		fmt.Println("Setup default port as 587")
		SmtpPort = "587"
	}
	SmtpHost, exist := os.LookupEnv("INIT_SMTP_HOST")
	if !exist {
		err = errors.Join(err, errors.New("Missing environment variable INIT_SMTP_HOST"))

	}

	SmtpSenderEmail, exist := os.LookupEnv("INIT_SMTP_SENDER_EMAIL")
	if !exist {
		err = errors.Join(err, errors.New("Missing environment variable INIT_SMTP_SENDER_EMAIL"))

	}
	VerificationLinkHost, exist := os.LookupEnv("INIT_VERI_LINK_BASE")
	if !exist {
		err = errors.Join(err, errors.New("Missing environment variable INIT_VERI_LINK_BASE"))

	}

	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	return envConfig{
		Env:                  env,
		LogPath:              logPath,
		DbConnStr:            connString,
		DbName:               dbname,
		ListenPort:           listenPort,
		SmtpPass:             smtpPass,
		SmtpUser:             SmtpUser,
		SmtpPort:             SmtpPort,
		SmtpHost:             SmtpHost,
		SmtpSenderEmail:      SmtpSenderEmail,
		VerificationLinkHost: VerificationLinkHost,
	}

}

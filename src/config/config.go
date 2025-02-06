package config

import (
	"errors"
	"fmt"
	"os"
)

type envConfig struct {
	Env        string
	DbConnStr  string
	DbName     string
	LogPath    string
	ListenPort string
}

func NewEnvConfig() envConfig {
	var err error
	env, exist := os.LookupEnv("INIT_ENV")
	if !exist {
		err = errors.Join(err, errors.New("Missing environment variable INIT_ENV"))
	}

	logPath, exist := os.LookupEnv("KN_INIT_LOG_PATH")
	if !exist {
		err = errors.Join(err, errors.New("Missing environment variable KN_INIT_LOG_PATH"))
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

	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	return envConfig{
		Env:        env,
		LogPath:    logPath,
		DbConnStr:  connString,
		DbName:     dbname,
		ListenPort: listenPort,
	}

}

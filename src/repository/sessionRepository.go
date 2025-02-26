package repository

import "INIT-SGGW/InIT-Azure-backend-01.Register/model"

type SessionRepository interface {
	CreateNewSession(user model.User) (sessionId string, err error)
	UpdateSession(sessionId string, status string) error
}

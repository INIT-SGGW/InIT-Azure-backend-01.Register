package service

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/repository"

	"go.uber.org/zap"
)

type Service struct {
	logger     *zap.Logger
	repository repository.RegisterRepository
}

func NewService(logger *zap.Logger, repository repository.RegisterRepository) *Service {
	return &Service{
		logger:     logger,
		repository: repository,
	}
}

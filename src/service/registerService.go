package service

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/model"
	"INIT-SGGW/InIT-Azure-backend-01.Register/repository"
	"context"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"go.uber.org/zap"
)

type RegisterService struct {
	service    *Service
	repository repository.RegisterRepository
}

type UserService interface {
	CreateNewUser(ctx context.Context, dboUser model.User) error
	MapUserRequestToDBO(request model.RegisterUserRequest) (model.User, error)
}

func NewRegisterService(logger *zap.Logger, repository repository.RegisterRepository) RegisterService {
	return RegisterService{
		service:    NewService(logger),
		repository: repository,
	}
}
func (serv RegisterService) CreateNewUser(ctx context.Context, dboUser model.User) error {
	defer serv.service.logger.Sync()

	serv.service.logger.Debug("In CreateNewUser method")

	err := serv.repository.CreateUserInDB(dboUser, ctx)
	if err != nil {
		serv.service.logger.Error("Error inserting data to database",
			zap.Error(err))
		return err
	}
	return nil

}
func (serv RegisterService) MapUserRequestToDBO(request model.RegisterUserRequest) (model.User, error) {
	defer serv.service.logger.Sync()

	serv.service.logger.Debug("Start mapping user object to DBO user ")

	hashPass, err := serv.hashPassword(request.Body.Password)
	if err != nil {
		serv.service.logger.Error("Error Hashing password",
			zap.Error(err))
		return model.User{}, err
	}
	uniqueVerificationToken := uuid.NewString()
	dboUser := model.User{
		ID:                primitive.NewObjectID(),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		FirstName:         request.Body.FirstName,
		LastName:          request.Body.LastName,
		Password:          hashPass,
		Emails:            []string{request.Body.Email},
		DateOfBirth:       request.Body.DateOfBirth,
		Agreement:         request.Body.IsAggrementFulfielled,
		Verified:          false,
		VerificationToken: uniqueVerificationToken,
	}

	return dboUser, nil

}

func (serv RegisterService) SendConfirmationEmail(ctx context.Context, email string) error {
	defer serv.service.logger.Sync()
	serv.service.logger.Info("Send email")

	return nil
}

func (RegisterService) hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
func (RegisterService) checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

package service

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/model"
	"INIT-SGGW/InIT-Azure-backend-01.Register/repository"
	"context"
	"time"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"go.uber.org/zap"
)

type AdminRequestService struct {
	service    *Service
	repository repository.AdminRepository
}

type AdminService interface {
	CreateNewAdmin(ctx context.Context, dboAdmin model.Admin) error
	MapAdminRequestToDBO(request model.RegisterAdminRequest) (model.Admin, error)
	VerifyAdminToken(ctx context.Context, email, verificationToken string) error
	AuthenticateAdmin(email, password string, ctx context.Context) (bool, model.Admin, error)
	GetAdminById(id string, ctx context.Context) (model.Admin, error)
}

func NewAdminService(logger *zap.Logger, repository repository.AdminRepository) AdminRequestService {
	return AdminRequestService{
		service:    NewService(logger),
		repository: repository,
	}
}

func (serv AdminRequestService) CreateNewAdmin(ctx context.Context, dboAdmin model.Admin) error {
	defer serv.service.logger.Sync()

	serv.service.logger.Debug("In CreateNewAdmin method")

	err := serv.repository.CreateAdminInDB(dboAdmin, ctx)
	if mongo.IsDuplicateKeyError(err) {
		serv.service.logger.Error("User with following email already exists",
			zap.Error(err))
		return err
	}
	if err != nil {
		serv.service.logger.Error("Error inserting data to database",
			zap.Error(err))
		return err
	}
	serv.service.logger.Info("Sucessfully create admin user in database",
		zap.String("admin", dboAdmin.DiscordUsername))

	return nil
}

func (serv AdminRequestService) MapAdminRequestToDBO(request model.RegisterAdminRequest) (model.Admin, error) {
	defer serv.service.logger.Sync()

	hashPasswored, err := serv.service.hashPassword(request.Body.Password)
	if err != nil {
		serv.service.logger.Error("Error Hashing password",
			zap.Error(err))
		return model.Admin{}, err
	}

	uniqueVerificationToken := uuid.NewString()

	admin := model.Admin{
		ID:                primitive.NewObjectID(),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		FirstName:         request.Body.FirstName,
		LastName:          request.Body.LastName,
		DiscordUsername:   request.Body.DiscordUsername,
		Email:             request.Body.Email,
		Password:          hashPasswored,
		VerificationToken: uniqueVerificationToken,
		Verified:          false,
		AdminPermissions:  []string{"read-all"},
	}

	return admin, nil
}

func (serv AdminRequestService) VerifyAdminToken(ctx context.Context, email, verificationToken string) error {
	defer serv.service.logger.Sync()

	dbEmail, err := serv.repository.GetAdminEmailByToken(ctx, verificationToken)
	if err == mongo.ErrNilDocument {
		serv.service.logger.Error("The token is not found in database",
			zap.Error(err))
		return err
	}
	if err != nil {
		serv.service.logger.Error("Error in email retreival",
			zap.Error(err))
		return err
	}
	if email != dbEmail {
		serv.service.logger.Error("None of emails match the user data in the database")
		return mongo.ErrNilDocument
	}

	err = serv.repository.VerifyAdmin(ctx, email)
	if err != nil {
		serv.service.logger.Error("Error verifying admin",
			zap.Error(err))
		return err
	}
	serv.service.logger.Info("Succesfully verified admin email")

	return nil
}
func (serv AdminRequestService) AuthenticateAdmin(email, password string, ctx context.Context) (bool, model.Admin, error) {
	defer serv.service.logger.Sync()

	adminDbo, err := serv.repository.GetAdminByEmail(ctx, email)
	if err == mongo.ErrNilDocument {
		serv.service.logger.Error("The email is not found in database",
			zap.Error(err))
		return false, model.Admin{}, err
	}
	if err != nil {
		serv.service.logger.Error("Error in database retreival",
			zap.Error(err))
		return false, model.Admin{}, err
	}
	serv.service.logger.Info("Admin sucesfully retreive from database")

	isAuthenticate := serv.service.checkPasswordHash(password, adminDbo.Password)

	return isAuthenticate, adminDbo, err
}
func (serv AdminRequestService) GetAdminById(id string, ctx context.Context) (model.Admin, error) {
	defer serv.service.logger.Sync()

	adminDbo, err := serv.repository.GetAdminByID(ctx, id)
	if err == mongo.ErrNilDocument {
		serv.service.logger.Error("Cannot find the admin in database",
			zap.Error(err))
		return model.Admin{}, err
	}
	if err != nil {
		serv.service.logger.Error("Error retreiving admin from database",
			zap.Error(err))
		return model.Admin{}, err
	}
	serv.service.logger.Info("Succesfully get user from database",
		zap.String("userId", adminDbo.ID.String()))

	return adminDbo, nil
}

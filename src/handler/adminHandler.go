package handler

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/model"
	"INIT-SGGW/InIT-Azure-backend-01.Register/repository"
	"INIT-SGGW/InIT-Azure-backend-01.Register/service"
	"context"
	"net/http"

	"go.mongodb.org/mongo-driver/mongo"

	"github.com/go-chi/jwtauth"

	"go.uber.org/zap"
)

type AdminHandler struct {
	handler      *Handler
	adminService service.AdminService
	emailService service.EmailTemplateService
	authToken    *jwtauth.JWTAuth
}

func NewAdminHandler(logger *zap.Logger, authToken *jwtauth.JWTAuth, repository repository.MongoRepository, user, password, emailHost, emailPort, emailSender, verificationLinkHost string) *AdminHandler {

	return &AdminHandler{
		handler:      NewHandler(logger),
		adminService: service.NewAdminService(logger, repository),
		emailService: service.NewEmailService(logger, user, password, emailHost, emailPort, emailSender, verificationLinkHost, repository),
		authToken:    authToken,
	}
}

func (han AdminHandler) HandleRegisterAdminRequest(ctx context.Context, input *model.RegisterAdminRequest) (*model.RegisterAdminResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleRegisterAdminRequest method")

	resp := model.RegisterAdminResponse{}
	adminDbo, err := han.adminService.MapAdminRequestToDBO(*input)
	if err != nil {
		resp.Body.Message = err.Error()
		resp.Body.Status = "Error in mapping to admin to dboAdmin "
		resp.Status = http.StatusBadRequest
		return &resp, err
	}

	err = han.adminService.CreateNewAdmin(ctx, adminDbo)
	if mongo.IsDuplicateKeyError(err) {
		han.handler.logger.Error("Admin with following email already exists",
			zap.Error(err))
		resp.Body.Message = "duplicate user"
		resp.Body.Status = "user already exist"
		resp.Status = http.StatusBadRequest
		return &resp, err
	}
	if err != nil {
		resp.Body.Message = err.Error()
		resp.Body.Status = "admin not created"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}

	err = han.emailService.SendAdminVerificationEmail(ctx, adminDbo)
	if err != nil {
		resp.Body.Message = err.Error()
		resp.Body.Status = "confirmation email not send"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}

	resp.Body.Status = "created"
	resp.Status = http.StatusCreated

	return &resp, nil

}

func (han AdminHandler) HandleVerificationAdminRequest(ctx context.Context, input *model.VerificationAdminRequest) (*model.VerificationAdminResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleVerificationUserRequest method")
	resp := model.VerificationAdminResponse{}

	err := han.adminService.VerifyAdminToken(ctx, input.Body.Email, input.Body.VerificationToken)
	if err == mongo.ErrNilDocument {
		resp.Body.Message = err.Error()
		resp.Body.Status = "mail and token do not match"
		resp.Status = http.StatusUnauthorized
		return &resp, err
	}
	if err != nil {
		resp.Body.Message = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}

	resp.Body.Status = "verified"
	resp.Status = http.StatusCreated

	return &resp, nil
}

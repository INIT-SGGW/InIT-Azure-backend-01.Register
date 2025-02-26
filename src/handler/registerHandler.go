package handler

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/model"
	"INIT-SGGW/InIT-Azure-backend-01.Register/repository"
	"INIT-SGGW/InIT-Azure-backend-01.Register/service"
	"context"
	"net/http"

	"go.uber.org/zap"
)

type RegisterHandler struct {
	handler         *Handler
	registerService service.UserService
	emailService    service.EmailTemplateService
}

func NewRegisterHandler(logger *zap.Logger, repository repository.MongoRepository, user, password, emailHost, emailPort, emailSender string) *RegisterHandler {

	return &RegisterHandler{
		handler:         NewHandler(logger),
		registerService: service.NewRegisterService(logger, repository),
		emailService:    service.NewEmailService(logger, user, password, emailHost, emailPort, emailSender, repository),
	}
}

func (han RegisterHandler) HandleRegisterUserRequest(ctx context.Context, input *model.RegisterUserRequest) (*model.RegisterUserResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleRegisterUserRequest method")

	resp := model.RegisterUserResponse{}
	userDbo, err := han.registerService.MapUserRequestToDBO(*input)
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "Error in mapping to user to dboUser "
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}
	err = han.registerService.CreateNewUser(ctx, userDbo)
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "User not created"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}
	err = han.emailService.SendUserVerificationEmail(ctx, userDbo)
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "Confirmation email not send"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}

	resp.Body.Status = "created"
	resp.Status = http.StatusCreated

	return &resp, nil

}

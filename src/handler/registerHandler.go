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
	handler *Handler
	service *service.RegisterService
}

func NewRegisterHandler(logger *zap.Logger, repository repository.RegisterRepository) *RegisterHandler {

	return &RegisterHandler{
		handler: NewHandler(logger),
		service: service.NewRegisterService(logger, repository),
	}
}

func (han RegisterHandler) HandleRegisterUserRequest(ctx context.Context, input *model.RegisterUserRequest) (*model.RegisterUserResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleRegisterUserRequest method")

	resp := model.RegisterUserResponse{}
	err := han.service.CreateNewUser(ctx, *input)
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "User not created"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}
	err = han.service.SendConfirmationEmail(ctx, input.Body.Email)
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

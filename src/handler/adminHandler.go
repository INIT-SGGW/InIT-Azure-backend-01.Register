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

func NewAdminHandler(logger *zap.Logger, authToken *jwtauth.JWTAuth, repository repository.MongoRepository, user, password, emailHost, emailPort, emailSender, ICCDomain, HADomain string) *AdminHandler {

	return &AdminHandler{
		handler:      NewHandler(logger),
		adminService: service.NewAdminService(logger, repository),
		emailService: service.NewEmailService(logger, user, password, emailHost, emailPort, emailSender, ICCDomain, HADomain, repository),
		authToken:    authToken,
	}
}

func (han AdminHandler) HandleRegisterAdminRequest(ctx context.Context, input *model.RegisterAdminRequest) (*model.RegisterAdminResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleRegisterAdminRequest method")

	resp := model.RegisterAdminResponse{}

	_, err := jwtauth.VerifyToken(han.authToken, input.JwtCookie.Value)
	if err != nil {
		han.handler.logger.Error("Error verifying token",
			zap.Error(err))

		resp.Body.Message = "Admin is not logged in"
		resp.Body.Status = "User not created"
		resp.Status = http.StatusUnauthorized

		return &resp, err
	}

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

	adminDbo, err := han.adminService.MapAdminVerifyRequestToDBO(*input)
	if err != nil {
		han.handler.logger.Error("Error when mapping admin user data",
			zap.Error(err))

		resp.Body.Message = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}

	err = han.adminService.UpdateAdminInDB(ctx, adminDbo)
	if err != nil {
		han.handler.logger.Error("Error when updating the admin user data",
			zap.Error(err))

		resp.Body.Message = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}

	resp.Body.Status = "verified"
	resp.Status = http.StatusCreated

	return &resp, nil
}

func (han AdminHandler) HandleLoginAdminRequest(ctx context.Context, input *model.LoginAdminRequest) (*model.LoginAdminResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleLoginAdminRequest method")
	resp := model.LoginAdminResponse{}

	isAuthenticate, admin, err := han.adminService.AuthenticateAdmin(input.Body.Email, input.Body.Password, ctx)
	if err != nil && err != mongo.ErrNilDocument {

		resp.Body.Message = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}
	if !isAuthenticate || err == mongo.ErrNilDocument {
		resp.Body.Message = "authentication failed"
		resp.Body.Status = "email and password do not match"
		resp.Status = http.StatusUnauthorized
		return &resp, err
	}

	han.handler.logger.Info("User authenticated creating token")

	claims := map[string]interface{}{"id": admin.ID, "email": input.Body.Email, "privilage": admin.AdminPermissions}
	_, tokenString, err := han.authToken.Encode(claims)
	if err != nil {
		han.handler.logger.Error("Error creating token",
			zap.Error(err))

		resp.Body.Message = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}
	han.handler.logger.Info("Sucesfully create token with claims")

	resp.SetCookie = http.Cookie{
		Name:     "jwt-init-admin",
		Value:    tokenString,
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}

	resp.Body.UserID = admin.ID.String()
	resp.Body.Status = "sucesfully log in"
	resp.Status = http.StatusOK

	return &resp, nil
}

func (han AdminHandler) HandleLogoutAdminRequest(ctx context.Context, input *model.LogoutAdminRequest) (*model.LogoutAdminResponse, error) {
	defer han.handler.logger.Sync()

	resp := model.LogoutAdminResponse{}

	resp.SetCookie = http.Cookie{
		Name:     "jwt-init-admin",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}

	resp.Body.Message = "user sucesfully logout"

	return &resp, nil

}

func (han AdminHandler) HandleGetAdminRequest(ctx context.Context, input *model.GetAdminRequest) (*model.GetAdminResponse, error) {
	defer han.handler.logger.Sync()

	idFromInput := input.Id
	resp := model.GetAdminResponse{}
	resp.Status = http.StatusUnauthorized
	resp.Body.FirstName = "empty"
	resp.Body.LastName = "empty"
	resp.Body.Email = "empty"
	resp.Body.DiscordUsername = "empty"
	resp.Body.IsVerified = false

	token, err := jwtauth.VerifyToken(han.authToken, input.JwtCookie.Value)
	if err != nil {
		han.handler.logger.Error("Error verifying token",
			zap.Error(err))

		return &resp, err
	}
	claims := token.PrivateClaims()

	id, exist := claims["id"]
	if !exist {
		han.handler.logger.Error("The id field is not present in the token")
		return &resp, err

	}

	if id.(string) != idFromInput {
		han.handler.logger.Error("The id field do not match with the one in request")

		return &resp, err
	}
	han.handler.logger.Info("Admin token and id sucesfully verified")

	adminDbo, err := han.adminService.GetAdminById(idFromInput, ctx)
	if err != nil {
		han.handler.logger.Error("Error retreiving user from database",
			zap.Error(err))

		resp.Status = http.StatusInternalServerError
		return &resp, err
	}
	han.handler.logger.Info("Admin sucesfully retreive from database")

	resp.Body.FirstName = adminDbo.FirstName
	resp.Body.LastName = adminDbo.LastName
	resp.Body.Email = adminDbo.Email
	resp.Body.DiscordUsername = adminDbo.DiscordUsername
	resp.Body.IsVerified = adminDbo.Verified

	han.handler.logger.Info("Admin sucesfully mapped to response",
		zap.String("userId", adminDbo.ID.String()),
	)

	resp.Status = http.StatusOK

	return &resp, nil
}

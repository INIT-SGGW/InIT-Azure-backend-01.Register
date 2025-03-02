package handler

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/model"
	"INIT-SGGW/InIT-Azure-backend-01.Register/repository"
	"INIT-SGGW/InIT-Azure-backend-01.Register/service"
	"context"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth"

	"go.mongodb.org/mongo-driver/mongo"

	"go.uber.org/zap"
)

type RegisterHandler struct {
	handler         *Handler
	registerService service.UserService
	emailService    service.EmailTemplateService
	authToken       *jwtauth.JWTAuth
}

func NewRegisterHandler(logger *zap.Logger, authToken *jwtauth.JWTAuth, repository repository.MongoRepository, user, password, emailHost, emailPort, emailSender, verificationLinkHost string) *RegisterHandler {

	return &RegisterHandler{
		handler:         NewHandler(logger),
		registerService: service.NewRegisterService(logger, repository),
		emailService:    service.NewEmailService(logger, user, password, emailHost, emailPort, emailSender, verificationLinkHost, repository),
		authToken:       authToken,
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

func (han RegisterHandler) HandleVerificationUserRequest(ctx context.Context, input *model.UserVerificationRequest) (*model.VerificationUserResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleVerificationUserRequest method")
	resp := model.VerificationUserResponse{}

	err := han.registerService.VerifyEmailByToken(ctx, input.Body.Email, input.Body.VerificationToken)
	if err == mongo.ErrNilDocument {
		resp.Body.Error = err.Error()
		resp.Body.Status = "mail and token do not match"
		resp.Status = http.StatusUnauthorized
		return &resp, err
	}
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}

	resp.Body.Status = "verified"
	resp.Status = http.StatusCreated

	return &resp, nil
}

func (han RegisterHandler) HandleLoginUserRequest(ctx context.Context, input *model.LoginUserRequest) (*model.LoginUserResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleLoginUserRequest method")
	resp := model.LoginUserResponse{}

	isAuthenticate, user, err := han.registerService.AuthenticateUser(input.Body.Email, input.Body.Password, ctx)
	if err != nil && err != mongo.ErrNilDocument {

		resp.Body.Error = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}
	if !isAuthenticate {
		resp.Body.Error = err.Error()
		resp.Body.Status = "email and password do not match"
		resp.Status = http.StatusUnauthorized
		return &resp, err
	}

	claims := map[string]interface{}{"id": user.ID, "email": input.Body.Email}
	_, tokenString, err := han.authToken.Encode(claims)
	if err != nil {
		han.handler.logger.Error("Error creating token",
			zap.Error(err))

		resp.Body.Error = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, err
	}
	resp.SetCookie = http.Cookie{
		Name:   "jwt",
		Value:  tokenString,
		MaxAge: 3600,
	}

	resp.Body.UserID = user.ID.String()
	resp.Body.Status = "sucesfully log in"
	resp.Status = http.StatusOK

	return &resp, nil
}

func (han RegisterHandler) HandleLogoutRequest(ctx context.Context, input *model.LogoutUserRequest) (*model.LogoutResponse, error) {
	defer han.handler.logger.Sync()

	resp := model.LogoutResponse{}

	resp.SetCookie = http.Cookie{
		Name:   "jwt",
		Value:  "",
		MaxAge: -1,
	}

	resp.Body.Message = "user sucesfully logout"

	return &resp, nil
}

func (han RegisterHandler) HandleGetUserRequest(ctx context.Context, input *model.GetUserRequest) (*model.GetUserResponse, error) {
	defer han.handler.logger.Sync()

	idFromInput := input.Id
	resp := model.GetUserResponse{}
	resp.Status = http.StatusUnauthorized
	resp.Body.Id = "empty"
	resp.Body.FirstName = "empty"
	resp.Body.LastName = "empty"
	resp.Body.Emails = []string{"empty"}
	resp.Body.DateOfBirth = time.Time{}
	resp.Body.IsVerified = false
	resp.Body.IsAggrementFulfielled = false

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
	han.handler.logger.Info("User token and id sucesfully verified")

	userDbo, err := han.registerService.GetUserById(idFromInput, ctx)
	if err != nil {
		han.handler.logger.Error("Error retreiving user from database",
			zap.Error(err))

		resp.Status = http.StatusInternalServerError
		return &resp, err
	}
	han.handler.logger.Info("User sucesfully retreive from database")

	resp.Body.Id = userDbo.ID.String()
	resp.Body.FirstName = userDbo.FirstName
	resp.Body.LastName = userDbo.LastName
	resp.Body.Emails = userDbo.Emails
	resp.Body.DateOfBirth = userDbo.DateOfBirth
	resp.Body.IsAggrementFulfielled = userDbo.Agreement
	resp.Body.IsVerified = userDbo.Verified
	resp.Body.AcademicYear = userDbo.AcademicYear
	resp.Body.Faculty = userDbo.Faculty
	resp.Body.Degree = userDbo.Degree

	han.handler.logger.Info("User sucesfully mapped to response",
		zap.String("userId", userDbo.ID.String()),
	)

	resp.Status = http.StatusOK

	return &resp, nil
}

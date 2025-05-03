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

func NewRegisterHandler(logger *zap.Logger, authToken *jwtauth.JWTAuth, repository repository.MongoRepository, user, password, emailHost, emailPort, emailSender, ICCDomain, HADomain string) *RegisterHandler {

	return &RegisterHandler{
		handler:         NewHandler(logger),
		registerService: service.NewRegisterService(logger, repository),
		emailService:    service.NewEmailService(logger, user, password, emailHost, emailPort, emailSender, ICCDomain, HADomain, repository),
		authToken:       authToken,
	}
}

func (han RegisterHandler) HandleRegisterUserRequest(ctx context.Context, input *model.RegisterUserRequest) (*model.RegisterUserResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleRegisterUserRequest method")

	resp := model.RegisterUserResponse{}
	userDbo, err := han.registerService.MapUserRequestToDBO(*&input.Body, false)
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "Error in mapping to user to dboUser "
		resp.Status = http.StatusBadRequest
		return &resp, nil
	}

	err = han.registerService.CreateNewUser(ctx, userDbo)
	if mongo.IsDuplicateKeyError(err) {
		han.handler.logger.Error("User with following email already exists",
			zap.Error(err))
		resp.Body.Error = "duplicate user"
		resp.Body.Status = "User already exist"
		resp.Status = http.StatusBadRequest
		return &resp, nil
	}
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "User not created"
		resp.Status = http.StatusInternalServerError
		return &resp, nil
	}
	err = han.emailService.SendUserVerificationEmail(ctx, input.Body.Service, userDbo)
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "Confirmation email not send"
		resp.Status = http.StatusInternalServerError
		return &resp, nil
	}

	resp.Body.Status = "created"
	resp.Status = http.StatusCreated

	return &resp, nil

}

func (han RegisterHandler) HandleRegisterUserFromInvitationRequest(ctx context.Context, input *model.RegisterUserFromInvitationRequest) (*model.RegisterUserResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleRegisterUserFromInvitationRequest method")
	resp := model.RegisterUserResponse{}

	err := han.registerService.VerifyEmailByToken(ctx, input.Body.Email, input.Body.VerificationToken)
	if err == mongo.ErrNoDocuments {
		resp.Body.Error = err.Error()
		resp.Body.Status = "mail and token do not match"
		resp.Status = http.StatusUnauthorized
		return &resp, nil
	}
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, nil
	}

	userDbo, err := han.registerService.MapUserRequestToDBO(input.Body.RegisterUserBody, true)
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "Error in mapping to user to dboUser "
		resp.Status = http.StatusBadRequest
		return &resp, nil
	}

	_, err = han.registerService.CreateUserFromInvitation(ctx, userDbo, input.Body.VerificationToken)
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "User not created"
		resp.Status = http.StatusInternalServerError
		return &resp, nil
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
	if err == mongo.ErrNoDocuments {
		resp.Body.Error = err.Error()
		resp.Body.Status = "mail and token do not match"
		resp.Status = http.StatusBadRequest
		return &resp, nil
	}
	if err != nil {
		resp.Body.Error = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, nil
	}

	resp.Body.Status = "verified"
	resp.Status = http.StatusCreated

	return &resp, nil
}

func (han RegisterHandler) HandleLoginUserRequest(ctx context.Context, input *model.LoginUserRequest) (*model.LoginUserResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleLoginUserRequest method")
	resp := model.LoginUserResponse{}

	isAuthenticate, user, err := han.registerService.AuthenticateUser(input.Body.Service, input.Body.Email, input.Body.Password, ctx)
	if err != nil && err != mongo.ErrNilDocument {

		resp.Body.Error = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, nil
	}
	if !isAuthenticate {
		resp.Body.Error = "authentication failed"
		resp.Body.Status = "email and password do not match"
		resp.Status = http.StatusUnauthorized
		return &resp, nil
	}

	claims := map[string]interface{}{
		"id":    user.ID,
		"email": input.Body.Email,
		"iat":   time.Now().Unix(),
	}

	_, tokenString, err := han.authToken.Encode(claims)
	if err != nil {
		han.handler.logger.Error("Error creating token",
			zap.Error(err))

		resp.Body.Error = err.Error()
		resp.Body.Status = "internal error"
		resp.Status = http.StatusInternalServerError
		return &resp, nil
	}
	resp.SetCookie = http.Cookie{
		Name:     "jwt",
		Value:    tokenString,
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}

	err = han.registerService.AssignUserToEvent(ctx, user.ID.Hex(), input.Body.Service, false)
	if err != nil {
		han.handler.logger.Error("Error assigning user to event",
			zap.String("event", input.Body.Service),
			zap.String("userId", user.ID.String()),
			zap.Error(err))
		resp.Body.Error = err.Error()
		resp.Body.Status = "user cannot be assigned to event"
		resp.Status = http.StatusBadRequest
		return &resp, nil
	}

	resp.Body.UserID = user.ID.String()
	resp.Body.Status = "sucesfully log in"
	resp.Status = http.StatusOK

	return &resp, nil
}

func (han RegisterHandler) HandleLogoutRequest(ctx context.Context, input *model.LogoutUserRequest) (*model.LogoutResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleLogoutRequest method")

	resp := model.LogoutResponse{}

	resp.SetCookie = http.Cookie{
		Name:     "jwt",
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

func (han RegisterHandler) HandleGetUserByIdRequest(ctx context.Context, input *model.GetUserByIdRequest) (*model.GetUserByIdResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleGetUserByIdRequest method")

	idFromInput := input.Id
	resp := model.GetUserByIdResponse{}
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

		return &resp, nil
	}
	claims := token.PrivateClaims()

	id, exist := claims["id"]
	if !exist {
		han.handler.logger.Error("The id field is not present in the token")
		return &resp, nil

	}

	if id.(string) != idFromInput {
		han.handler.logger.Error("The id field do not match with the one in request")

		return &resp, nil
	}
	han.handler.logger.Info("User token and id sucesfully verified")

	userDbo, err := han.registerService.GetUserById(idFromInput, ctx)
	if err != nil {
		han.handler.logger.Error("Error retreiving user from database",
			zap.Error(err))

		resp.Status = http.StatusInternalServerError
		return &resp, nil
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

func (han RegisterHandler) HandleGetUserByEmailRequest(ctx context.Context, input *model.GetUserByEmailRequest) (*model.GetUserByEmailResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleGetUserByEmailRequest method")

	emailFromInput := input.Email
	resp := model.GetUserByEmailResponse{}
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

		return &resp, nil
	}
	claims := token.PrivateClaims()

	email, exist := claims["email"]
	if !exist {
		han.handler.logger.Error("The email field is not present in the token")
		return &resp, nil

	}

	if email != emailFromInput {
		han.handler.logger.Error("The email field do not match with the one in request")

		return &resp, nil
	}
	han.handler.logger.Info("User token and id sucesfully verified")

	userDbo, err := han.registerService.GetUserByEmail(emailFromInput, ctx)
	if err != nil {
		han.handler.logger.Error("Error retreiving user from database",
			zap.Error(err))

		resp.Status = http.StatusInternalServerError
		return &resp, nil
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
	resp.Body.Occupation = userDbo.Occupation
	resp.Body.DietPreference = userDbo.DietPreference
	resp.Body.StudentIndex = userDbo.StudentIndex
	resp.Body.EventTags = userDbo.Events

	han.handler.logger.Info("User sucesfully mapped to response",
		zap.String("userId", userDbo.ID.String()),
	)

	resp.Status = http.StatusOK

	return &resp, nil
}

func (han RegisterHandler) HandleResendEmailRequest(ctx context.Context, input *model.ResendEmailRequest) (*model.ResendEmailResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleResendEmailRequest method")

	resp := model.ResendEmailResponse{}
	err := han.emailService.ResendVerificationEmail(ctx, input.Body.Service, input.Body.Email)
	if err == mongo.ErrNoDocuments {
		han.handler.logger.Error("Cannot find user in database",
			zap.String("email", input.Body.Email),
			zap.Error(err))

		resp.Body.Status = "user cannot be found"
		resp.Body.Message = "user for the email address not found"
		resp.Status = http.StatusBadRequest

		return &resp, nil
	}
	if err != nil {
		han.handler.logger.Error("Error resending email",
			zap.String("email", input.Body.Email),
			zap.Error(err))

		resp.Body.Status = "resending failed"
		resp.Body.Message = "internal error in resending email"
		resp.Status = http.StatusInternalServerError

		return &resp, nil
	}

	han.handler.logger.Info("Sucesfully resend verification email",
		zap.String("recipient", input.Body.Email))

	resp.Status = http.StatusOK
	resp.Body.Status = "resend"

	return &resp, nil
}

func (han RegisterHandler) HandleAddEmailRequest(ctx context.Context, input *model.AddEmailRequest) (*model.AddEmailResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleResendEmailRequest method")

	resp := model.AddEmailResponse{}

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

	dbUser, err := han.registerService.AddUserEmail(ctx, id.(string), input.Body.Email)
	if err != nil {
		han.handler.logger.Error("Error adding email to user",
			zap.Error(err))
		return &resp, err
	}

	err = han.emailService.SendEmailVerificationEmail(ctx, dbUser, input.Body.Email)
	if err != nil {
		han.handler.logger.Error("Error sending email",
			zap.Error(err))
		return &resp, err
	}

	han.handler.logger.Info("Sucesfully added email to user",
		zap.String("recipient", input.Body.Email))

	resp.Status = http.StatusOK
	resp.Body.Status = "email added"

	return &resp, nil
}

func (han RegisterHandler) HandleAssignToEventRequest(ctx context.Context, input *model.AssignToEventRequest) (*model.AssignToEventResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleAssignToEventRequest method")

	resp := model.AssignToEventResponse{}

	token, err := jwtauth.VerifyToken(han.authToken, input.JwtCookie.Value)
	if err != nil {
		han.handler.logger.Error("Error verifying token",
			zap.Error(err))

		resp.Status = http.StatusUnauthorized
		resp.Body.Status = "user not authenticated"
		resp.Body.Message = "Error in token verification"
		return &resp, nil
	}
	claims := token.PrivateClaims()

	id, exist := claims["id"]
	if !exist {
		han.handler.logger.Error("The id field is not present in the token")

		resp.Status = http.StatusUnauthorized
		resp.Body.Status = "user not authenticated"
		resp.Body.Message = "No user id in token"

		return &resp, nil
	}

	err = han.registerService.AssignUserToEvent(ctx, id.(string), input.Body.Event, true)
	if err != nil {
		han.handler.logger.Error("Error assigning user to event",
			zap.String("event", input.Body.Event),
			zap.String("userId", id.(string)),
			zap.Error(err))

		resp.Body.Status = "user cannot be assigned to event"
		resp.Body.Message = err.Error()
		resp.Status = http.StatusBadRequest

		return &resp, nil
	}

	han.handler.logger.Info("Sucesfully assigned user to event",
		zap.String("event", input.Body.Event))

	resp.Status = http.StatusOK
	resp.Body.Status = "resend"

	return &resp, nil
}

func (han RegisterHandler) HandleAppendTeamInvitationRequest(ctx context.Context, input *model.AppendTeamInvitationRequest) (*model.AppendTeamInvitationResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleAppendTeamInvitationRequest method")

	resp := model.AppendTeamInvitationResponse{}

	dbUser, err := han.registerService.GetUserByEmail(input.Body.Email, ctx)
	if err != nil && err != mongo.ErrNoDocuments {
		han.handler.logger.Error("Error retreiving user from database",
			zap.String("email", input.Body.Email),
		)

		resp.Status = http.StatusInternalServerError
		resp.Body.Status = "error retreiving user from databse"
		resp.Body.Message = err.Error()

		return &resp, err
	}

	if err == mongo.ErrNoDocuments {
		// creating new user
		han.handler.logger.Info("User not found in database, creating new temp user",
			zap.String("email", input.Body.Email),
		)
		dbUser, err = han.registerService.CreateNewTempUser(ctx, input.Body.Email)
		if err != nil {
			han.handler.logger.Error("Error creating new temp user",
				zap.String("email", input.Body.Email),
				zap.Error(err))

			resp.Status = http.StatusInternalServerError
			resp.Body.Status = "error creating new temp user"
			resp.Body.Message = err.Error()

			return &resp, err
		}
		han.handler.logger.Info("Sucesfully created new temp user",
			zap.String("email", input.Body.Email),
		)

		err = han.emailService.SendCreateUserEmail(ctx, dbUser)
		if err != nil {
			han.handler.logger.Error("Error sending an email",
				zap.String("email", dbUser.Emails[0]),
				zap.Error(err))

			resp.Status = http.StatusInternalServerError
			resp.Body.Status = "error sending email"
			resp.Body.Message = err.Error()

			return &resp, err
		}
	}

	if !input.Body.AddNotification {
		args := map[string]string{
			"teamId":   input.Body.TeamId,
			"teamName": input.Body.TeamName,
		}

		err = han.registerService.AppendNotificationToUser(ctx, dbUser.ID, "ha_team_invite", "ha", nil, args)
		if err != nil {
			han.handler.logger.Error("Error appending invitation to user",
				zap.String("teamId", input.Body.TeamId),
				zap.String("userId", dbUser.ID.String()),
				zap.Error(err))
			return &resp, err
		}
	}

	resp.Body.UserId = dbUser.ID.Hex()
	resp.Status = http.StatusOK
	resp.Body.Status = "appended"
	return &resp, nil
}

func (han RegisterHandler) HandleGetUserNotificationsRequest(ctx context.Context, input *model.GetUserNotificationsRequest) (*model.GetUserNotificationsResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleGetUserNotificationsRequest method")

	resp := model.GetUserNotificationsResponse{}

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

		resp.Status = http.StatusInternalServerError
		resp.Body.Status = "internal server error"
		resp.Body.Message = "No user id in token"
		return &resp, nil
	}

	if id.(string) != input.Id {
		han.handler.logger.Error("The id field do not match with the one in request")

		resp.Status = http.StatusForbidden
		resp.Body.Status = "user can't access other users notifications"
		resp.Body.Message = "The id field do not match with the one in request"
		return &resp, nil
	}

	dbNotifications, err := han.registerService.GetUserNotifications(ctx, input.Id, &input.Service)
	if err != nil {
		han.handler.logger.Error("Error retreiving user notifications from database",
			zap.String("userId", input.Id),
			zap.Error(err))
		resp.Status = http.StatusInternalServerError
		resp.Body.Status = "error retreiving user notifications from databse"
		resp.Body.Message = err.Error()
		return &resp, err
	}

	responseNotifications := make([]model.NotificationResponse, 0)
	for _, dbNoti := range dbNotifications {
		responseNotifications = append(responseNotifications, model.NotificationResponse{
			ID:      dbNoti.ID.Hex(),
			Type:    dbNoti.Type,
			Status:  dbNoti.Status,
			Service: dbNoti.Service,
			Event:   dbNoti.Event,
			Args:    dbNoti.Args,
		})
	}

	han.handler.logger.Info("Sucesfully mapped user notifications to response")

	resp.Body.Notifications = responseNotifications
	resp.Status = http.StatusOK

	return &resp, nil
}

func (han RegisterHandler) HandleChangeNotificationStatusRequest(ctx context.Context, input *model.ChangeNotificationStatusRequest) (*model.ChangeNotificationStatusResponse, error) {
	defer han.handler.logger.Sync()

	han.handler.logger.Debug("In HandleChangeNotificationStatusRequest method")

	resp := model.ChangeNotificationStatusResponse{}

	token, err := jwtauth.VerifyToken(han.authToken, input.JwtCookie.Value)
	if err != nil {
		han.handler.logger.Error("Error verifying token",
			zap.Error(err))
		resp.Status = http.StatusUnauthorized
		resp.Body.Status = "user not authenticated"
		resp.Body.Message = "Error in token verification"
		return &resp, nil
	}

	claims := token.PrivateClaims()
	id, exist := claims["id"]
	if !exist {
		han.handler.logger.Error("The id field is not present in the token")
		resp.Status = http.StatusUnauthorized
		resp.Body.Status = "user not authenticated"
		resp.Body.Message = "No user id in token"
		return &resp, nil
	}

	if id.(string) != input.UserId {
		han.handler.logger.Error("The id field do not match with the one in request")
		resp.Status = http.StatusForbidden
		resp.Body.Status = "user can't access other users notifications"
		resp.Body.Message = "The id field do not match with the one in request"
		return &resp, nil
	}
	han.handler.logger.Info("User token and id sucesfully verified")

	err = han.registerService.ChangeNotificationStatus(ctx, input.UserId, input.NotificationId, input.Body.Status)
	if err != nil {
		han.handler.logger.Error("Error changing notification status",
			zap.String("userId", input.UserId),
			zap.String("notificationId", input.NotificationId),
			zap.Error(err))

		resp.Status = http.StatusInternalServerError
		resp.Body.Status = "error changing notification status"
		resp.Body.Message = err.Error()
		return &resp, err
	}

	resp.Status = http.StatusOK
	resp.Body.Status = "sucesfully changed notification status"

	return &resp, nil

}

package main

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/config"
	"INIT-SGGW/InIT-Azure-backend-01.Register/handler"
	"INIT-SGGW/InIT-Azure-backend-01.Register/initializer"
	"INIT-SGGW/InIT-Azure-backend-01.Register/model"
	"INIT-SGGW/InIT-Azure-backend-01.Register/repository"
	"fmt"

	"go.uber.org/zap"

	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth"
)

func main() {
	config := config.NewEnvConfig()
	logger := initializer.CreateLogger(config.LogPath)
	defer logger.Sync()

	logger.Info("Starting service",
		zap.String("Environment", config.Env))

	authToken := jwtauth.New("HS256", []byte(config.JWTSecret), nil)

	repo := repository.NewRegisterRepository(config.DbConnStr, config.DbName, logger)
	registerHandler := handler.NewRegisterHandler(logger, authToken, repo, config.SmtpUser, config.SmtpPass, config.SmtpHost, config.SmtpPort, config.SmtpSenderEmail, config.ICCDomain, config.HADomain)
	adminHandler := handler.NewAdminHandler(logger, authToken, repo, config.SmtpUser, config.SmtpPass, config.SmtpHost, config.SmtpPort, config.SmtpSenderEmail, config.ICCDomain, config.HADomain)

	r := chi.NewRouter()

	r.Use(initializer.CorsHandler)
	r.Use(initializer.New(logger))
	r.Use(initializer.Recovery)
	r.Route("/register/user", func(r chi.Router) {
		r.Use(jwtauth.Verifier(authToken))
		r.Use(jwtauth.Authenticator)
	})

	r.Group(func(r chi.Router) {
		r.Route("/register/admin", func(r chi.Router) {
			r.Use(jwtauth.Verifier(authToken))
			r.Use(jwtauth.Authenticator)
		})
	})

	api := createHumaApi("KN INIT Website Register API", "1.0.0", r)
	addRoutes(api, *registerHandler, config.ApiKey)
	addAdminRoutes(api, *adminHandler, config.AdminApiKey)

	http.ListenAndServe(fmt.Sprintf(":%s", config.ListenPort), r)

}

func createHumaApi(title, version string, r chi.Router) huma.API {
	humaConfig := huma.DefaultConfig(title, version)
	humaConfig.DocsPath = "/register/docs"
	humaConfig.OpenAPIPath = "/register/openapi"
	humaConfig.SchemasPath = "/register/schemas"

	api := humachi.New(r, humaConfig)
	return api
}

func addRoutes(api huma.API, handler handler.RegisterHandler, apiKey string) {

	middleware := func(ctx huma.Context, next func(huma.Context)) {
		// Read a cookie by name.
		sessionCookie, err := huma.ReadCookie(ctx, "jwt")
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusUnauthorized,
				"JWT cookie is not present", fmt.Errorf("Not logged in user"),
			)
			return
		}

		ctx = huma.WithValue(ctx, "jwt", sessionCookie.Value)
		ctx.SetHeader("jwt", sessionCookie.Value)
		next(ctx)
	}

	apiKeyMiddleware := func(ctx huma.Context, next func(huma.Context)) {
		// Read a cookie by name.
		providedKey := ctx.Header("INIT-API-KEY")

		if providedKey != apiKey {
			huma.WriteErr(api, ctx, http.StatusUnauthorized,
				"the provided api key is incorrect", fmt.Errorf("Accessing from unauthorized source"),
			)
			return
		}
		next(ctx)
	}

	huma.Get(api, "/hearthbeat", func(ctx context.Context, input *struct{}) (*model.HealthProbeResponse, error) {
		resp := &model.HealthProbeResponse{}
		resp.Body.Status = "I'm Alive!"
		return resp, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "register-user",
		Method:      http.MethodPost,
		Path:        "/register/user",
		Summary:     "Register user",
		Description: "Register user and send confirmation email to provided adress with unique token for account verification",
	}, handler.HandleRegisterUserRequest)

	huma.Register(api, huma.Operation{
		OperationID: "verify-user",
		Method:      http.MethodPost,
		Path:        "/register/verifiy",
		Summary:     "Verify user email",
		Description: "Based on provided token and email, verify the user email",
	}, handler.HandleVerificationUserRequest)

	huma.Register(api, huma.Operation{
		OperationID: "login-user",
		Method:      http.MethodPost,
		Path:        "/register/login",
		Summary:     "Login user",
		Description: "Login user sending JWT cookie to client for further authentication",
	}, handler.HandleLoginUserRequest)

	huma.Register(api, huma.Operation{
		OperationID: "logout-user",
		Method:      http.MethodPost,
		Path:        "/register/logout",
		Summary:     "Logout user",
		Description: "Remove JWT token from client",
	}, handler.HandleLogoutRequest)

	huma.Register(api, huma.Operation{
		OperationID: "get-user",
		Method:      http.MethodGet,
		Path:        "/register/user/id/{id}",
		Summary:     "Get user by id",
		Description: "Get user data from database",
		Middlewares: huma.Middlewares{middleware},
	}, handler.HandleGetUserByIdRequest)

	huma.Register(api, huma.Operation{
		OperationID: "get-user",
		Method:      http.MethodGet,
		Path:        "/register/user/email/{email}",
		Summary:     "Get user by email",
		Description: "Get user data from database",
		Middlewares: huma.Middlewares{middleware},
	}, handler.HandleGetUserByEmailRequest)

	huma.Register(api, huma.Operation{
		OperationID: "resend-user-verification",
		Method:      http.MethodPost,
		Path:        "/register/verify/resend",
		Summary:     "Resend verification email",
		Description: "If user exist in the database the verification email is resend to the provided adress",
	}, handler.HandleResendEmailRequest)

	huma.Register(api, huma.Operation{
		OperationID: "add-email",
		Method:      http.MethodPost,
		Path:        "/register/add/email",
		Summary:     "Add email to user's account",
		Description: "Add email to user's account and send confirmation email to provided adress with unique token for account verification",
		Middlewares: huma.Middlewares{middleware},
	}, handler.HandleAddEmailRequest)

	huma.Register(api, huma.Operation{
		OperationID: "assign-to-event",
		Method:      http.MethodPost,
		Path:        "/register/event/assign",
		Summary:     "Assign user to event",
		Description: "If user exist in the database, assign user to the event",
		Middlewares: huma.Middlewares{middleware},
	}, handler.HandleAssignToEventRequest)

	huma.Register(api, huma.Operation{
		OperationID: "ceate-user-from-invitation",
		Method:      http.MethodPost,
		Path:        "/register/user/invitation",
		Summary:     "Create user from invitation",
		Description: "Create user from invitation and add notification",
	}, handler.HandleRegisterUserFromInvitationRequest)

	huma.Register(api, huma.Operation{
		OperationID: "append-team-invitation",
		Method:      http.MethodPost,
		Path:        "/register/team/invitation",
		Summary:     "Append team invitation",
		Description: "Append team invitation to user, if user doesn't exist, create user from email",
		Middlewares: huma.Middlewares{apiKeyMiddleware},
	}, handler.HandleAppendTeamInvitationRequest)

	huma.Register(api, huma.Operation{
		OperationID: "get-notifications",
		Method:      http.MethodGet,
		Path:        "/register/user/{id}/notifications",
		Summary:     "Get notfications",
		Description: "Get notfications for user, based on service. If service not specified, all notifications are returned",
		Middlewares: huma.Middlewares{middleware},
	}, handler.HandleGetUserNotificationsRequest)

	huma.Register(api, huma.Operation{
		OperationID: "change-notification-status",
		Method:      http.MethodPatch,
		Path:        "/register/user/{userId}/notifications/{notificationId}/status",
		Summary:     "Change notification status",
		Description: "Change notification status for user",
		Middlewares: huma.Middlewares{middleware},
	}, handler.HandleChangeNotificationStatusRequest)
}

func addAdminRoutes(api huma.API, handler handler.AdminHandler, adminApiKey string) {

	authMiddleware := func(ctx huma.Context, next func(huma.Context)) {
		// Read a cookie by name.
		sessionCookie, err := huma.ReadCookie(ctx, "jwt-init-admin")
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusUnauthorized,
				"jwt-init-admin cookie is not present", fmt.Errorf("Not logged as admin"),
			)
			return
		}

		ctx = huma.WithValue(ctx, "jwt-init-admin", sessionCookie.Value)
		ctx.SetHeader("jwt-init-admin", sessionCookie.Value)
		next(ctx)
	}

	apiKeyMiddleware := func(ctx huma.Context, next func(huma.Context)) {
		// Read a cookie by name.
		providedKey := ctx.Header("X-INIT-ADMIN-API-KEY")
		print(providedKey + " " + adminApiKey)
		if providedKey != adminApiKey {
			huma.WriteErr(api, ctx, http.StatusUnauthorized,
				"the provided api key is incorrect", fmt.Errorf("Not logged as admin"),
			)
			return
		}
		next(ctx)
	}

	huma.Register(api, huma.Operation{
		OperationID: "register-admin",
		Method:      http.MethodPost,
		Path:        "/register/admin",
		Summary:     "Register admin",
		Description: "Register admin and send confirmation email to provided adress with unique token for account verification",
		Middlewares: huma.Middlewares{apiKeyMiddleware, authMiddleware},
	}, handler.HandleRegisterAdminRequest)

	huma.Register(api, huma.Operation{
		OperationID: "verify-admin",
		Method:      http.MethodPost,
		Path:        "/register/admin/verifiy",
		Summary:     "Verify admin email",
		Description: "Based on provided token and email, verify the admin email and update admin data",
		Middlewares: huma.Middlewares{apiKeyMiddleware},
	}, handler.HandleVerificationAdminRequest)

	huma.Register(api, huma.Operation{
		OperationID: "login-admin",
		Method:      http.MethodPost,
		Path:        "/register/admin/login",
		Summary:     "Login admin",
		Description: "Login admin sending JWT cookie to client for further authentication",
		Middlewares: huma.Middlewares{apiKeyMiddleware},
	}, handler.HandleLoginAdminRequest)

	huma.Register(api, huma.Operation{
		OperationID: "logout-admin",
		Method:      http.MethodPost,
		Path:        "/register/admin/logout",
		Summary:     "Logout admin",
		Description: "Remove JWT token from client",
		Middlewares: huma.Middlewares{apiKeyMiddleware},
	}, handler.HandleLogoutAdminRequest)

	huma.Register(api, huma.Operation{
		OperationID: "get-admin",
		Method:      http.MethodGet,
		Path:        "/register/admin/{id}",
		Summary:     "Get admin by id",
		Description: "Get admin data from database",
		Middlewares: huma.Middlewares{apiKeyMiddleware, authMiddleware},
	}, handler.HandleGetAdminRequest)
}

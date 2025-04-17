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
	registerHandler := handler.NewRegisterHandler(logger, authToken, repo, config.SmtpUser, config.SmtpPass, config.SmtpHost, config.SmtpPort, config.SmtpSenderEmail, config.VerificationLinkHost)
	adminHandler := handler.NewAdminHandler(logger, authToken, repo, config.SmtpUser, config.SmtpPass, config.SmtpHost, config.SmtpPort, config.SmtpSenderEmail, config.VerificationLinkHost)

	r := chi.NewRouter()

	if config.Env == "DEV" {
		r.Use(initializer.CorsHandler)
	}
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
	addRoutes(api, *registerHandler)
	addAdminRoutes(api, *adminHandler, config.ApiKey)

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

func addRoutes(api huma.API, handler handler.RegisterHandler) {

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
		Path:        "/register/user/{id}",
		Summary:     "Get user by id",
		Description: "Get user data from database",
		Middlewares: huma.Middlewares{middleware},
	}, handler.HandleGetUserRequest)

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
}

func addAdminRoutes(api huma.API, handler handler.AdminHandler, apiKey string) {

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
		print(providedKey + " " + apiKey)
		if providedKey != apiKey {
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

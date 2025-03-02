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
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth"
)

func main() {
	config := config.NewEnvConfig()
	logger := initializer.CreateLogger(config.LogPath)
	defer logger.Sync()

	c := cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://initcodingchallenge.pl"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-ICC-API-KEY", "JWT"},
		AllowCredentials: false,
		MaxAge:           300,
	})

	logger.Info("Starting service",
		zap.String("Environment", config.Env))

	authToken := jwtauth.New("HS256", []byte(config.JWTSecret), nil)

	repo := repository.NewRegisterRepository(config.DbConnStr, config.DbName, logger)
	registerHandler := handler.NewRegisterHandler(logger, authToken, repo, config.SmtpUser, config.SmtpPass, config.SmtpHost, config.SmtpPort, config.SmtpSenderEmail, config.VerificationLinkHost)

	r := chi.NewRouter()
	r.Use(c)
	r.Use(initializer.New(logger))
	r.Use(initializer.AutorizeRequest(config.ApiKey, logger))
	r.Route("/api/v1/register/user", func(r chi.Router) {
		r.Use(jwtauth.Verifier(authToken))
		r.Use(jwtauth.Authenticator)
	})

	api := createHumaApi("KN INIT Website Register API", "1.0.0", r)
	addRoutes(api, *registerHandler)

	http.ListenAndServe(fmt.Sprintf(":%s", config.ListenPort), r)
}

func createHumaApi(title, version string, r chi.Router) huma.API {
	humaConfig := huma.DefaultConfig(title, version)
	humaConfig.DocsPath = "/api/v1/register/docs"
	humaConfig.OpenAPIPath = "/api/v1/register/openapi"
	humaConfig.SchemasPath = "/api/v1/register/schemas"

	api := humachi.New(r, humaConfig)
	return api
}

func addRoutes(api huma.API, handler handler.RegisterHandler) {

	middleware := func(ctx huma.Context, next func(huma.Context)) {
		// Read a cookie by name.
		sessionCookie, err := huma.ReadCookie(ctx, "jwt")
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusUnauthorized,
				"JWT cookie do not present", fmt.Errorf("Not logged in user"),
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
		Path:        "/api/v1/register/user",
		Summary:     "Register user",
		Description: "Register user and send confirmation email to provided adress with unique token for account verification",
	}, handler.HandleRegisterUserRequest)

	huma.Register(api, huma.Operation{
		OperationID: "verify-user",
		Method:      http.MethodPost,
		Path:        "/api/v1/register/verifiy",
		Summary:     "Verify user email",
		Description: "Based on provided token and email, verify the user email",
	}, handler.HandleVerificationUserRequest)

	huma.Register(api, huma.Operation{
		OperationID: "login-user",
		Method:      http.MethodPost,
		Path:        "/api/v1/register/login",
		Summary:     "Login user",
		Description: "Login user sending JWT cookie to client for further authentication",
	}, handler.HandleLoginUserRequest)

	huma.Register(api, huma.Operation{
		OperationID: "logout-user",
		Method:      http.MethodPost,
		Path:        "/api/v1/register/logout",
		Summary:     "Logout user",
		Description: "Remove JWT token from client",
	}, handler.HandleLogoutRequest)

	huma.Register(api, huma.Operation{
		OperationID: "get-user",
		Method:      http.MethodGet,
		Path:        "/api/v1/register/user/{id}",
		Summary:     "Get user by id",
		Description: "Get user data from database",
		Middlewares: huma.Middlewares{middleware},
	}, handler.HandleGetUserRequest)
}

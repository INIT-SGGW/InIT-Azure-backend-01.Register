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
)

func main() {
	config := config.NewEnvConfig()
	logger := initializer.CreateLogger(config.LogPath)
	defer logger.Sync()

	logger.Info("Starting service",
		zap.String("Environment", config.Env))

	repo := repository.NewMongoRepository(config.DbConnStr, config.DbName, logger)
	registerHandler := handler.NewRegisterHandler(logger, repo)

	r := chi.NewRouter()
	r.Use(initializer.New(logger))

	standardApiRouter := chi.NewRouter()
	r.Mount("/v1/api", standardApiRouter)

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
}

package main

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/initializer"
	"context"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

type HealthProbeResponse struct {
	Body struct {
		Status string `json:"status" example:"I'm Alive!" doc:"Health check"`
	}
}

func main() {
	logger := initializer.CreateLogger()
	fmt.Println("Hello InIT!")
	r := chi.NewRouter()
	r.Use(initializer.New(logger))

	standardApiRouter := chi.NewRouter()

	r.Mount("/v1/api", standardApiRouter)

	api := humachi.New(r, huma.DefaultConfig("KN INIT Website API", "1.0.0"))

	huma.Get(api, "/hearthbeat", func(ctx context.Context, input *struct{}) (*HealthProbeResponse, error) {
		resp := &HealthProbeResponse{}
		resp.Body.Status = "I'm Alive!"
		return resp, nil
	})

	// huma.Register(api, huma.Operation{
	// 	OperationID: "register-user",
	// 	Method:      http.MethodPost,
	// 	Path:        "/api/v1/register/user",
	// 	Summary:     "Register user",
	// 	Description: "Register user and send confirmation email to provided adress with unique token for account verification",
	// }, registerServ.HandleRegisterUserRequest)

	http.ListenAndServe(":3131", r)
}

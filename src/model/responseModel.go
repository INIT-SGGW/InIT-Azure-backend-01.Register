package model

import "net/http"

type HealthProbeResponse struct {
	Body struct {
		Status string `json:"status" example:"I'm Alive!" doc:"Health check"`
	}
}

type RegisterUserResponse struct {
	Status int
	Body   struct {
		Status string `json:"status" example:"created" doc:"Status of creating user request"`
		Error  string `json:"error,omitempty" example:"user already exist" doc:"Errors in user creation"`
	}
}
type VerificationUserResponse struct {
	Status int
	Body   struct {
		Status string `json:"status" example:"verified" doc:"Status of email verification"`
		Error  string `json:"error,omitempty" example:"email and token do not match" doc:"Errors in user verification"`
	}
}

type LoginUserResponse struct {
	SetCookie http.Cookie `header:"Set-Cookie"`
	Status    int
	Body      struct {
		Status string `json:"status" example:"sucesfully log in" doc:"Status of login operation"`
		Error  string `json:"error,omitempty" example:"email and password do not match" doc:"Errors in user authentication"`
	}
}
type LogoutResponse struct {
	SetCookie http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Message string `json:"message" example:"user sucesfully logout" doc:"Message from backend server"`
	}
}

package model

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

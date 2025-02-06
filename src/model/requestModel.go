package model

import "time"

type RegisterUserRequest struct {
	Body struct {
		FirstName             string    `json:"firstName" example:"John" doc:"User first name"`
		LastName              string    `json:"lastName" example:"Doe" doc:"User last name"`
		Email                 string    `son:"email" example:"john.doe@example.com" doc:"User email, the confirmation will be send to that adress"`
		Password              string    `json:"password" example:"Pa$$word123!" doc:"User Password"`
		DateOfBirth           time.Time `json:"dateOfBirth" example:"2000-03-23T07:00:00+01:00" doc:"Date of birth for age information"`
		IsAggrementFulfielled bool      `json:"aggrement" example:"true" doc:"Check if the aggrement is approved"`
	}
}

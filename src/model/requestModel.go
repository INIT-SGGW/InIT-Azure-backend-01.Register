package model

import (
	"net/http"
	"time"
)

type RegisterUserRequest struct {
	Body struct {
		FirstName             string    `json:"firstName" example:"John" doc:"User first name"`
		LastName              string    `json:"lastName" example:"Doe" doc:"User last name"`
		Email                 string    `json:"email" example:"john.doe@example.com" doc:"User email, the confirmation will be send to that adress"`
		Password              string    `json:"password" example:"Pa$$word123!" doc:"User Password"`
		DateOfBirth           time.Time `json:"dateOfBirth" example:"2000-03-23T07:00:00+01:00" doc:"Date of birth for age information"`
		IsAggrementFulfielled bool      `json:"aggrement" example:"true" doc:"Check if the aggrement is approved"`
	}
}

type UserVerificationRequest struct {
	Body struct {
		Email             string `json:"email" example:"john.doe@example.com" doc:"User email already registered to InIT backend"`
		VerificationToken string `json:"verificationToken" example:"d4f8c767-8e92-4504-8565-3369d78dbc30" doc:"Unique token genereated for each user in registration provided in link as token"`
	}
}

type LoginUserRequest struct {
	Body struct {
		Email    string `json:"email" example:"john.doe@example.com" doc:"User email send to log in"`
		Password string `json:"password" example:"secretPa$$word!" doc:"Password send for authentication"`
	}
}

type LogoutUserRequest struct{}

type GetUserRequest struct {
	JwtCookie http.Cookie `cookie:"jwt"`
	Id        string      `path:"id" example:"67c0df2b24397b2e860be392" doc:"requested user id"`
}

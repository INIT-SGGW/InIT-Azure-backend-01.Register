package model

import (
	"net/http"
	"time"
)

type RegisterUserBody struct {
	Service               string    `json:"service" example:"ha" doc:"Name of a service, where user is trying to register"`
	FirstName             string    `json:"firstName" example:"John" doc:"User first name"`
	LastName              string    `json:"lastName" example:"Doe" doc:"User last name"`
	Email                 string    `json:"email" example:"john.doe@example.com" doc:"User email, the confirmation will be send to that adress"`
	Password              string    `json:"password" example:"Pa$$word123!" doc:"User Password"`
	DateOfBirth           time.Time `json:"dateOfBirth" example:"2000-03-23T07:00:00+01:00" doc:"Date of birth for age information"`
	IsAggrementFulfielled bool      `json:"aggrement" example:"true" doc:"Check if the aggrement is approved"`

	// ICC data
	StudentIndex *string `json:"studentIndex,omitempty" example:"222222" doc:"Student index"`
	AcademicYear *int    `json:"academicYear,omitempty" example:"3" doc:"Academic year of student"`
	Faculty      *string `json:"faculity,omitempty" example:"Wydzial Budownictwa i Inzynieri Srodowiska" doc:"Faculty on the sggw, where student is assigned"`
	Degree       *string `json:"degree,omitempty" example:"Bachelor" doc:"deggree of studies student attend to"`

	// HA data
	Occupation     *string `json:"occupation,omitempty" example:"Student" doc:"Occupation of user"`
	DietPreference *string `json:"dietPreference,omitempty" example:"Vegetarian" doc:"Diet preferences of user"`
}

type RegisterUserRequest struct {
	Body RegisterUserBody
}

type RegisterUserFromInvitationRequest struct {
	Body struct {
		VerificationToken string `json:"verificationToken" example:"d4f8c767-8e92-4504-8565-3369d78dbc30" doc:"Unique token genereated for each user in registration provided in link as token"`

		RegisterUserBody
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
		Service  string `json:"service" example:"ha" doc:"Name of a service, where user is trying to log in"`
		Email    string `json:"email" example:"john.doe@example.com" doc:"User email send to log in"`
		Password string `json:"password" example:"secretPa$$word!" doc:"Password send for authentication"`
	}
}

type LogoutUserRequest struct{}

type GetUserByIdRequest struct {
	JwtCookie http.Cookie `cookie:"jwt"`
	Id        string      `path:"id" example:"67c0df2b24397b2e860be392" doc:"requested user id"`
}

type UpdateUserRequest struct {
	Body struct {
		FirstName             string    `json:"firstName" example:"John" doc:"User first name"`
		LastName              string    `json:"lastName" example:"Doe" doc:"User last name"`
		AcademicYear          int       `json:"academicYear" example:"3" doc:"Academic year of student"`
		Faculty               string    `json:"faculity" example:"Wydzial Budownictwa i Inzynieri Srodowiska" doc:"Faculty on the sggw, where student is assigned"`
		Degree                string    `json:"degree" example:"Bachelor" doc:"deggree of studies student attend to"`
		DateOfBirth           time.Time `json:"dateOfBirth" example:"2000-03-23T07:00:00+01:00" doc:"Date of birth for age information"`
		IsAggrementFulfielled bool      `json:"aggrement" example:"true" doc:"Check if the aggrement is approved"`
	}
}

type ResendEmailRequest struct {
	Body struct {
		Service string `json:"service" example:"ha" doc:"Name of a service, where user is trying to register"`
		Email   string `json:"email" example:"john.doe@example.com" doc:"User email, the confirmation will be resend to that adress if already exist in database"`
	}
}

// Admin Endpoints

type RegisterAdminRequest struct {
	ApiKey    string      `header:"X-INIT-ADMIN-API-KEY"`
	JwtCookie http.Cookie `cookie:"jwt-init-admin"`

	Body struct {
		Email string `json:"email" example:"john.doe@example.com" doc:"User email, the confirmation will be send to that adress"`
	}
}

type VerificationAdminRequest struct {
	ApiKey string `header:"X-INIT-ADMIN-API-KEY"`

	Body struct {
		Email             string `json:"email" example:"john.doe@example.com" doc:"Admin email already registered to InIT backend"`
		VerificationToken string `json:"verificationToken" example:"d4f8c767-8e92-4504-8565-3369d78dbc30" doc:"Unique token genereated for each admin user in registration provided in link as token"`
		FirstName         string `json:"firstName" example:"John" doc:"Admin first name"`
		LastName          string `json:"lastName" example:"Doe" doc:"Admin last name"`
		DiscordUsername   string `json:"discordUsername" example:"JohnDoe" doc:"Admin username in InIT discord server"`
		Password          string `json:"password" example:"Pa$$word123!" doc:"User Password"`
	}
}

type LoginAdminRequest struct {
	ApiKey string `header:"X-INIT-ADMIN-API-KEY"`

	Body struct {
		Email    string `json:"email" example:"john.doe@example.com" doc:"Admin email send to log in"`
		Password string `json:"password" example:"secretPa$$word!" doc:"Password send for authentication"`
	}
}

type LogoutAdminRequest struct {
	ApiKey string `header:"X-INIT-ADMIN-API-KEY"`
}

type GetAdminRequest struct {
	ApiKey    string      `header:"X-INIT-ADMIN-API-KEY"`
	JwtCookie http.Cookie `cookie:"jwt-init-admin"`
	Id        string      `path:"id" example:"67c0df2b24397b2e860be392" doc:"requested admin id"`
}

type AddEmailRequest struct {
	JwtCookie http.Cookie `cookie:"jwt"`

	Body struct {
		Email string `json:"email" example:"john.doe@example.com" doc:"User email, the confirmation will be send to that adress"`
	}
}

type AssignToEventRequest struct {
	JwtCookie http.Cookie `cookie:"jwt"`

	Body struct {
		Event string `json:"event" example:"ha25" doc:"Event name to assign user"`
	}
}

type AppendTeamInvitationRequest struct {
	ApiKey string `header:"INIT-API-KEY"`

	Body struct {
		Email    string `json:"email" example:"john.doe@example.com" doc:"User email, who will be invited to the team"`
		TeamId   string `json:"teamId" example:"67c0df2b24397b2e860be392" doc:"Team id to which user will be invited"`
		TeamName string `json:"teamName" example:"Team name" doc:"Team name to which user will be invited"`
	}
}

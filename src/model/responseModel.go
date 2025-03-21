package model

import (
	"net/http"
	"time"
)

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
		UserID string `json:"userId,omitempty" example:"67c0df2b24397b2e860be392" doc:"Unique user identifier"`
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

type GetUserResponse struct {
	Status int

	Body struct {
		Id                    string    `json:"id" example:"67c0df2b24397b2e860be392" doc:"Unique user identifier"`
		FirstName             string    `json:"firstName" example:"John" doc:"User first name"`
		LastName              string    `json:"lastName" example:"Doe" doc:"User last name"`
		Emails                []string  `json:"emails" example:"john.doe@example.com,john.doe@johndoe.com" doc:"User emails"`
		AcademicYear          int       `json:"academicYear" example:"3" doc:"Academic year of student"`
		Faculty               string    `json:"faculity" example:"Wydzial Budownictwa i Inzynieri Srodowiska" doc:"Faculty on the sggw, where student is assigned"`
		Degree                string    `json:"degree" example:"Bachelor" doc:"deggree of studies student attend to"`
		DateOfBirth           time.Time `json:"dateOfBirth" example:"2000-03-23T07:00:00+01:00" doc:"Date of birth for age information"`
		IsVerified            bool      `json:"verified" example:"true" doc:"true if user verified any of emails"`
		IsAggrementFulfielled bool      `json:"aggrement" example:"true" doc:"Check if the aggrement is approved"`
	}
}

type ResendEmailResponse struct {
	Status int
	Body   struct {
		Status  string `json:"status" example:"resend" doc:"Status of resending the email"`
		Message string `json:"message,omitempty" example:"user for the email address not found" doc:"Errors in resending email"`
	}
}

// Admin endpoints responses
type RegisterAdminResponse struct {
	Status int
	Body   struct {
		Status  string `json:"status" example:"created" doc:"Status of creating user request"`
		Message string `json:"message,omitempty" example:"admin already exist" doc:"Errors and additional message about admin user creation"`
	}
}

type VerificationAdminResponse struct {
	Status int
	Body   struct {
		Status  string `json:"status" example:"verified" doc:"Status of email verification"`
		Message string `json:"message,omitempty" example:"email and token do not match" doc:"Errors and information in admin verification"`
	}
}

type LoginAdminResponse struct {
	SetCookie http.Cookie `header:"Set-Cookie"`
	Status    int
	Body      struct {
		UserID  string `json:"userId,omitempty" example:"67c0df2b24397b2e860be392" doc:"Unique admin identifier"`
		Status  string `json:"status" example:"sucesfully log in" doc:"Status of login operation"`
		Message string `json:"message,omitempty" example:"email and password do not match" doc:"Errors in user authentication"`
	}
}
type LogoutAdminResponse struct {
	SetCookie http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Message string `json:"message" example:"user sucesfully logout" doc:"Message from backend server"`
	}
}

type GetAdminResponse struct {
	Status int

	Body struct {
		FirstName       string `json:"firstName" example:"John" doc:"Admin first name"`
		LastName        string `json:"lastName" example:"Doe" doc:"Admin last name"`
		DiscordUsername string `json:"discordUsername" example:"JohnDoe" doc:"Username in InIT discord server"`
		Email           string `json:"email" example:"john.doe@example.com" doc:"Admin email, the confirmation will be send to that adress"`
		IsVerified      bool   `json:"verified" example:"true" doc:"true if admin has verified email"`
	}
}

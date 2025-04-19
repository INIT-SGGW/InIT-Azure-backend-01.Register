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

type GetUserByIdResponse struct {
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

type GetUserByEmailResponse struct {
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
		StudentIndex          string    `json:"studentIndex" example:"222222" doc:"Student index"`
		Occupation            string    `json:"occupation" example:"Student" doc:"Occupation of user"`
		DietPreference        string    `json:"dietPreference" example:"Vegetarian" doc:"Diet preferences of user"`
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

type AddEmailResponse struct {
	Status int
	Body   struct {
		Status  string `json:"status" example:"verified" doc:"Status of email verification"`
		Message string `json:"message,omitempty" example:"email and token do not match" doc:"Errors and information in admin verification"`
	}
}

type AssignToEventResponse struct {
	Status int

	Body struct {
		Status  string `json:"status" example:"assigned" doc:"Status of assigning user to event"`
		Message string `json:"message,omitempty" example:"user for the email address not found" doc:"Errors in assigning user to event"`
	}
}

type AppendTeamInvitationResponse struct {
	Status int

	Body struct {
		Status  string `json:"status" example:"appended" doc:"Status of appending team invitation"`
		Message string `json:"message,omitempty" example:"user not found" doc:"Errors in appending invitation to user"`
	}
}

type NotificationResponse struct {
	ID      string            `json:"_id" example:"67c0df2b24397b2e860be392" doc:"Unique notification identifier"`
	Type    string            `json:"type" example:"ha_team_invite" doc:"Type of notification"`
	Status  string            `json:"status" example:"not-read" doc:"Status of notification"`
	Service string            `json:"service" example:"ha" doc:"Name of a service, which notification is assigned to"`
	Event   *string           `json:"event,omitempty" example:"ha_25" doc:"Event name, which notification is assigned to"`
	Args    map[string]string `json:"args,omitempty" example:"{\"teamId\":\"67c0df2b24397b2e860be392\"}" doc:"Arguments for notification, which are used to create notification message"`
}

type GetUserNotificationsResponse struct {
	Status int

	Body struct {
		Notifications []NotificationResponse `json:"notifications" example:"[{\"_id\":\"67c0df2b24397b2e860be392\",\"type\":\"ha_team_invite\",\"status\":\"not-read\",\"service\":\"ha\",\"event\":\"ha_25\",\"args\":{\"teamId\":\"67c0df2b24397b2e860be392\"}}]" doc:"List of notifications for user"`
		Status        string                 `json:"status" example:"success" doc:"Status of getting notifications"`
		Message       string                 `json:"message,omitempty" example:"user not found" doc:"Errors in getting notifications"`
	}
}

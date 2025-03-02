package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID                primitive.ObjectID `bson:"_id"`
	CreatedAt         time.Time          `bson:"created_at"`
	UpdatedAt         time.Time          `bson:"updated_at"`
	FirstName         string             `bson:"first_name"`
	LastName          string             `bson:"last_name"`
	Password          string             `bson:"password"`
	Emails            []string           `bson:"emails"`
	AcademicYear      int                `bson:"academic_year"`
	Faculty           string             `bson:"faculity"`
	Degree            string             `bson:"degree"`
	DateOfBirth       time.Time          `bson:"date_of_birth"`
	Agreement         bool               `bson:"agreement"`
	StudentIndex      string             `bson:"student_index,omitempty"`
	VerificationToken string             `bson:"token"`
	Verified          bool               `bson:"verified"`
	Events            []string           `bson:"events,omitempty"`
}

type EmailTemplate struct {
	ID                    primitive.ObjectID `bson:"_id"`
	CreatedAt             time.Time          `bson:"created_at"`
	UpdatedAt             time.Time          `bson:"updated_at"`
	TemplateName          string             `bson:"template_name"`
	Subject               string             `bson:"subject"`
	TemplateHtmlBody      string             `bson:"template_html_body"`
	TemplateAlternateBody string             `bson:"template_alternate_text_body"`
	Description           string             `bson:"description,omitempty"`
	RecipientGroups       []string           `bson:"recipient_groups,omitempty"`
}

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
	DateOfBirth       time.Time          `bson:"date_of_birth"`
	Agreement         bool               `bson:"agreement"`
	StudentIndex      string             `bson:"student_index,omitempty"`
	VerificationToken string             `bson:"token"`
	Verified          bool               `bson:"verified"`
	Events            []string           `bson:"events,omitempty"`
}

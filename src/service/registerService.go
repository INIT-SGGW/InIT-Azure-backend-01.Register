package service

import (
	"INIT-SGGW/InIT-Azure-backend-01.Register/model"
	"INIT-SGGW/InIT-Azure-backend-01.Register/repository"
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"go.uber.org/zap"
)

type RegisterService struct {
	service    *Service
	repository repository.RegisterRepository
}

type UserService interface {
	CreateNewUser(ctx context.Context, dboUser model.User) error
	MapUserRequestToDBO(request model.RegisterUserBody, verified bool) (model.User, error)
	VerifyEmailByToken(ctx context.Context, email, verificationToken string) error
	AuthenticateUser(service string, email, password string, ctx context.Context) (bool, model.User, error)
	GetUserById(id string, ctx context.Context) (model.User, error)
	AddUserEmail(ctx context.Context, id string, email string) (model.User, error)
	AssignUserToEvent(ctx context.Context, id string, event string) error
	CreateUserFromInvitation(ctx context.Context, user model.User, token string) (model.User, error)
}

func NewRegisterService(logger *zap.Logger, repository repository.RegisterRepository) RegisterService {
	return RegisterService{
		service:    NewService(logger),
		repository: repository,
	}
}
func (serv RegisterService) CreateNewUser(ctx context.Context, dboUser model.User) error {
	defer serv.service.logger.Sync()

	serv.service.logger.Debug("In CreateNewUser method")

	err := serv.repository.CreateUserInDB(dboUser, ctx)
	if mongo.IsDuplicateKeyError(err) {
		serv.service.logger.Error("User with following email already exists",
			zap.Error(err))
		return err
	}
	if err != nil {
		serv.service.logger.Error("Error inserting data to database",
			zap.Error(err))
		return err
	}
	return nil

}

func (serv RegisterService) validateRegisterBody(request model.RegisterUserBody) error {
	defer serv.service.logger.Sync()

	serv.service.logger.Debug("In validateRegisterBody method")
	switch request.Service {
	case "icc":
		{
			isSggwEmail := serv.verifySggwEmail(request.Email)

			if !isSggwEmail {
				serv.service.logger.Error("Provided email is not sggw email ")
				return errors.New("invalid sggw email")
			}

			if request.StudentIndex == nil {
				serv.service.logger.Error("Student index is a required field")
				return errors.New("student index is a required field")
			}
			if request.AcademicYear == nil {
				serv.service.logger.Error("Academic year is a required field")
				return errors.New("academic year is a required field")
			}
			if request.Faculty == nil {
				serv.service.logger.Error("Faculty is a required field")
				return errors.New("faculty is a required field")
			}
			if request.Degree == nil {
				serv.service.logger.Error("Degree is a required field")
				return errors.New("degree is a required field")
			}
		}
	case "ha":
		{
			if request.Occupation == nil {
				serv.service.logger.Error("Occupation is a required field")
				return errors.New("occupation is a required field")
			}
			if request.DietPreference == nil {
				serv.service.logger.Error("Diet preference is a required field")
				return errors.New("diet preference is a required field")
			}

		}
	default:
		{
			serv.service.logger.Error("Service is not supported", zap.String("service", request.Service))
			return errors.New("service is not supported")
		}
	}

	return nil
}

func (serv RegisterService) createUserModel(request model.RegisterUserBody, verified bool) (model.User, error) {
	defer serv.service.logger.Sync()

	hashPass, err := serv.service.hashPassword(request.Password)
	if err != nil {
		serv.service.logger.Error("Error Hashing password",
			zap.Error(err))
		return model.User{}, err
	}
	uniqueVerificationToken := uuid.NewString()

	modelUser := model.User{
		ID:                primitive.NewObjectID(),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		FirstName:         request.FirstName,
		LastName:          request.LastName,
		Password:          hashPass,
		Emails:            []string{request.Email},
		DateOfBirth:       request.DateOfBirth,
		Agreement:         request.IsAggrementFulfielled,
		Verified:          verified,
		VerificationToken: uniqueVerificationToken,
	}

	switch request.Service {
	case "icc":
		{
			modelUser.StudentIndex = *request.StudentIndex
			modelUser.AcademicYear = *request.AcademicYear
			modelUser.Faculty = *request.Faculty
			modelUser.Degree = *request.Degree
			modelUser.Events = []string{"icc"}
		}
	case "ha":
		{
			modelUser.Occupation = *request.Occupation
			modelUser.DietPreference = *request.DietPreference
			modelUser.Events = []string{"ha"}
		}
	default:
		{
			serv.service.logger.Error("Service is not supported", zap.String("service", request.Service))
			return model.User{}, errors.New("service is not supported")
		}
	}

	return modelUser, nil
}

func (serv RegisterService) MapUserRequestToDBO(request model.RegisterUserBody, verified bool) (model.User, error) {
	defer serv.service.logger.Sync()

	serv.service.logger.Debug("Start mapping user object to DBO user ")

	err := serv.validateRegisterBody(request)
	if err != nil {
		serv.service.logger.Error("Error in validation of user request",
			zap.Error(err))
		return model.User{}, err
	}

	dboUser, err := serv.createUserModel(request, verified)
	if err != nil {
		serv.service.logger.Error("Error in creating user model",
			zap.Error(err))
		return model.User{}, err
	}
	serv.service.logger.Info("User model created")

	return dboUser, nil
}

func (serv RegisterService) VerifyEmailByToken(ctx context.Context, email, verificationToken string) error {
	defer serv.service.logger.Sync()

	dbEmails, err := serv.repository.GetEmailByToken(ctx, verificationToken)
	if err == mongo.ErrNilDocument {
		serv.service.logger.Error("The token is not found in database",
			zap.Error(err))
		return err
	}
	if err != nil {
		serv.service.logger.Error("Error in email retreival",
			zap.Error(err))
		return err
	}
	isVerified := false
	for _, e := range dbEmails {
		if e == email {
			isVerified = true
			err = serv.repository.VerifyUser(ctx, e)
			if err != nil {
				serv.service.logger.Error("Error verifying user",
					zap.Error(err))
				return err
			}
			serv.service.logger.Info("Succesfully verified user email")
		}

	}
	if !isVerified {
		serv.service.logger.Error("None of emails match the user data in the database")
		return mongo.ErrNilDocument
	}

	return nil
}

func (serv RegisterService) AuthenticateUser(service string, email, password string, ctx context.Context) (bool, model.User, error) {
	defer serv.service.logger.Sync()

	if service == "icc" {
		isSggwEmail := serv.verifySggwEmail(email)

		if !isSggwEmail {
			serv.service.logger.Error("Provided email is not sggw email ")
			return false, model.User{}, errors.New("invalid sggw email")
		}
	}

	userDbo, err := serv.repository.GetUserByEmail(ctx, email)
	if err == mongo.ErrNilDocument {
		serv.service.logger.Error("The email is not found in database",
			zap.Error(err))
		return false, model.User{}, err
	}
	if err != nil {
		serv.service.logger.Error("Error in database retreival",
			zap.Error(err))
		return false, model.User{}, err
	}
	isAuthenticate := serv.service.checkPasswordHash(password, userDbo.Password)

	return isAuthenticate, userDbo, err

}

func (serv RegisterService) GetUserById(id string, ctx context.Context) (model.User, error) {
	defer serv.service.logger.Sync()

	userDbo, err := serv.repository.GetUserByID(ctx, id)
	if err == mongo.ErrNilDocument {
		serv.service.logger.Error("Cannot find the user in database",
			zap.Error(err))
		return model.User{}, err
	}
	if err != nil {
		serv.service.logger.Error("Error retreiving user from database",
			zap.Error(err))
		return model.User{}, err
	}
	serv.service.logger.Info("Succesfully get user from database",
		zap.String("userId", userDbo.ID.String()))

	return userDbo, nil
}

func (serv RegisterService) verifySggwEmail(email string) bool {
	defer serv.service.logger.Sync()

	emailRegex := `^[a-zA-Z]\d{6}@sggw\.edu\.pl$`

	re := regexp.MustCompile(emailRegex)

	if re.MatchString(email) {
		serv.service.logger.Info("Valid sggw email")
		return true
	} else {
		serv.service.logger.Info("Invalid sggw email")
		return false
	}
}

func (serv RegisterService) AddUserEmail(ctx context.Context, id string, email string) (model.User, error) {
	defer serv.service.logger.Sync()

	serv.service.logger.Debug("In AddUserEmail method")

	dbUser, err := serv.repository.AddUserEmail(ctx, id, email)
	if err != nil {
		serv.service.logger.Error("Error adding email to user",
			zap.Error(err))
		return model.User{}, err
	}

	return dbUser, nil
}

func (serv RegisterService) isEventValid(event string, events []string) bool {
	defer serv.service.logger.Sync()

	serv.service.logger.Debug("In isEventValid method")

	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}

func (serv RegisterService) AssignUserToEvent(ctx context.Context, id string, event string) error {
	defer serv.service.logger.Sync()

	events := []string{"ha_25", "icc"}

	if !serv.isEventValid(event, events) {
		serv.service.logger.Error("Provided event is not valid", zap.String("event", event))
		return errors.New("Provided event is invalid")
	}

	err := serv.repository.AssignUserToEvent(ctx, id, event)
	if err != nil {
		return err
	}

	return nil
}

func (serv RegisterService) CreateUserFromInvitation(ctx context.Context, user model.User, token string) (model.User, error) {
	defer serv.service.logger.Sync()

	serv.service.logger.Debug("In UpdateUserByEmail method")

	user, err := serv.repository.CreateUserFromInvitation(ctx, user, token)
	if err != nil {
		serv.service.logger.Error("Error updating user in database",
			zap.Error(err))
		return model.User{}, err
	}
	return user, nil
}

package repository

import (
	"context"
	"os"

	"errors"

	"INIT-SGGW/InIT-Azure-backend-01.Register/model"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

const (
	USER_COLLECTION_NAME           string = "Users"
	EMAIL_TEMPLATE_COLLECTION_NAME string = "Email-templates"
	ADMINS_COLLECTION_NAME         string = "Admins"
	NOTIFICATIONS_COLLECTION_NAME  string = "Notifications"
)

type MongoRepository struct {
	client   *mongo.Client
	database string
	logger   *zap.Logger
}

type RegisterRepository interface {
	CreateUserInDB(model.User, context.Context) error
	GetEmailByToken(ctx context.Context, verificationToken string) ([]string, error)
	VerifyUser(ctx context.Context, email string) error
	GetUserByEmail(ctx context.Context, email string) (model.User, error)
	GetUserByID(ctx context.Context, id string) (model.User, error)
	AddUserEmail(ctx context.Context, id string, email string) (model.User, error)
	AssignUserToEvent(ctx context.Context, id string, event string, strict bool) error
	CreateUserFromInvitation(ctx context.Context, user model.User, token string) (model.User, error)
	AppendNotificationToUser(ctx context.Context, notification model.Notification) error
	GetUserNotifications(ctx context.Context, userId string, service *string) ([]model.Notification, error)
	ChangeNotificationStatus(ctx context.Context, userId string, notificationId string, status string) error
}

func NewRegisterRepository(connectionString, dbname string, logger *zap.Logger) MongoRepository {
	defer logger.Sync()
	client, err := NewMongoClient(logger, connectionString, dbname)
	if err != nil {
		logger.Error("Fail to create Mongo client",
			zap.Error(err))
		os.Exit(2)
	}
	return MongoRepository{
		client:   client,
		database: dbname,
		logger:   logger}
}

func (repo MongoRepository) CreateUserInDB(user model.User, ctx context.Context) error {
	defer repo.logger.Sync()

	repo.logger.Debug("In CreateUserInDB method")

	coll := repo.client.Database(repo.database).Collection(USER_COLLECTION_NAME)

	result, err := coll.InsertOne(ctx, user)
	if mongo.IsDuplicateKeyError(err) {
		repo.logger.Error("User with following email already exists",
			zap.Error(err))
		return err
	}
	if err != nil {
		repo.logger.Error("Error inserting user into database",
			zap.Error(err))
		return err
	}

	repo.logger.Info("Sucesfully inserted user into database",
		zap.String("database", repo.database),
		zap.String("collection", USER_COLLECTION_NAME),
		zap.Any("userId", result.InsertedID))

	return nil
}

func (repo MongoRepository) GetEmailByToken(ctx context.Context, verificationToken string) ([]string, error) {
	defer repo.logger.Sync()

	repo.logger.Debug("In GetEmailByToken method")

	coll := repo.client.Database(repo.database).Collection(USER_COLLECTION_NAME)

	filter := bson.D{{Key: "token", Value: verificationToken}}
	var dboUser model.User

	err := coll.FindOne(ctx, filter).Decode(&dboUser)
	if err == mongo.ErrNoDocuments {
		repo.logger.Error("Cannot find following token in database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))

		return []string{}, err
	}
	if err != nil {
		repo.logger.Error("Error retreiving user from database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))
		return []string{}, err
	}

	return dboUser.Emails, err

}

func (repo MongoRepository) VerifyUser(ctx context.Context, email string) error {
	defer repo.logger.Sync()

	repo.logger.Debug("In VerifyUser method")

	coll := repo.client.Database(repo.database).Collection(USER_COLLECTION_NAME)

	filter := bson.D{{Key: "emails", Value: email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "verified", Value: true}}}}
	_, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		repo.logger.Error("Error updating record",
			zap.String("collectionName", USER_COLLECTION_NAME),
			zap.Error(err))
		return err
	}

	return nil

}

func (repo MongoRepository) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
	defer repo.logger.Sync()

	repo.logger.Debug("In GetUserByEmail method")

	coll := repo.client.Database(repo.database).Collection(USER_COLLECTION_NAME)

	filter := bson.D{{Key: "emails", Value: email}}
	var dboUser model.User

	err := coll.FindOne(ctx, filter).Decode(&dboUser)
	if err == mongo.ErrNoDocuments {
		repo.logger.Error("Cannot find following user in database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))

		return model.User{}, err
	}
	if err != nil {
		repo.logger.Error("Error retreiving user from database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))
		return model.User{}, err
	}
	repo.logger.Info("Sucesfully retreive user from database",
		zap.String("database", repo.database),
		zap.String("collection", USER_COLLECTION_NAME))

	return dboUser, err

}

func (repo MongoRepository) GetUserByID(ctx context.Context, id string) (model.User, error) {
	defer repo.logger.Sync()

	repo.logger.Debug("In GetUserByID method")

	coll := repo.client.Database(repo.database).Collection(USER_COLLECTION_NAME)
	queryId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		repo.logger.Error("Cannot parse id to ObjectId",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.String("id", id),
			zap.Error(err))
	}

	filter := bson.D{{Key: "_id", Value: queryId}}
	var dboUser model.User

	err = coll.FindOne(ctx, filter).Decode(&dboUser)
	if err == mongo.ErrNoDocuments {
		repo.logger.Error("Cannot find following user in database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.String("id", queryId.String()),
			zap.Error(err))

		return model.User{}, err
	}
	if err != nil {
		repo.logger.Error("Error retreiving user from database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))
		return model.User{}, err
	}
	repo.logger.Info("Sucesfully retreive user from database",
		zap.String("database", repo.database),
		zap.String("collection", USER_COLLECTION_NAME))

	return dboUser, err

}

func (repo MongoRepository) AddUserEmail(ctx context.Context, id string, email string) (model.User, error) {
	// add email to emails array, set verified to false and add token
	defer repo.logger.Sync()

	repo.logger.Debug("In AddUserEmail method")

	coll := repo.client.Database(repo.database).Collection(USER_COLLECTION_NAME)

	queryId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		repo.logger.Error("Cannot parse id to ObjectId",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.String("id", id),
			zap.Error(err))
	}

	// check if email is already in emails array
	filter := bson.D{{Key: "_id", Value: queryId}, {Key: "emails", Value: email}}
	result := coll.FindOne(ctx, filter)
	err = result.Err()
	if err != nil {
		if err == mongo.ErrNoDocuments {
			repo.logger.Debug("Email is not in emails array")
		} else {
			repo.logger.Error("Error retreiving user from database",
				zap.String("database", repo.database),
				zap.String("collection", USER_COLLECTION_NAME),
				zap.Error(err))
			return model.User{}, err
		}
	} else {
		repo.logger.Error("Email already exists in emails array",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.String("email", email))
		return model.User{}, errors.New("email already exists")
	}

	filter = bson.D{{Key: "_id", Value: queryId}}
	update := bson.D{
		{Key: "$addToSet", Value: bson.D{{Key: "emails", Value: email}}},
		{Key: "$set", Value: bson.D{{Key: "verified", Value: false}}},
		{Key: "$set", Value: bson.D{{Key: "token", Value: uuid.NewString()}}},
	}

	var updatedUser model.User

	err = coll.FindOneAndUpdate(
		ctx,
		filter,
		update,
		options.FindOneAndUpdate().SetReturnDocument(1)).Decode(&updatedUser)
	if err == mongo.ErrNoDocuments {
		repo.logger.Error("Cannot find following user in database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.String("id", queryId.String()),
			zap.Error(err))

		return model.User{}, err
	}
	if err != nil {
		repo.logger.Error("Error retreiving user from database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))
		return model.User{}, err
	}
	repo.logger.Info("Sucesfully retreive user from database",
		zap.String("database", repo.database),
		zap.String("collection", USER_COLLECTION_NAME))

	return updatedUser, err
}

func (repo MongoRepository) AssignUserToEvent(ctx context.Context, id string, event string, strict bool) error {
	// strict - if true, return error if user is already assigned to event
	defer repo.logger.Sync()
	repo.logger.Debug("In AssignUserToEvent method")
	repo.logger.Info("Assigning user to event", zap.String("event", event), zap.String("userID", id))

	coll := repo.client.Database(repo.database).Collection(USER_COLLECTION_NAME)

	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": objectId, "events": bson.M{"$ne": event}}
	update := bson.M{"$push": bson.M{"events": event}}

	result, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 && strict {
		return errors.New("User already assigned to event")
	}

	repo.logger.Info("Successfully assigned event to user")
	return nil
}

func (repo MongoRepository) CreateUserFromInvitation(ctx context.Context, user model.User, token string) (model.User, error) {
	defer repo.logger.Sync()

	repo.logger.Debug("In UpdateUserByEmail method")

	coll := repo.client.Database(repo.database).Collection(USER_COLLECTION_NAME)
	// filter user by email and token
	filter := bson.D{
		{Key: "emails", Value: user.Emails[0]},
	}
	// update user with data from user
	update := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "first_name", Value: user.FirstName},
			{Key: "password", Value: user.Password},
			{Key: "last_name", Value: user.LastName},
			{Key: "academic_year", Value: user.AcademicYear},
			{Key: "faculity", Value: user.Faculty},
			{Key: "degree", Value: user.Degree},
			{Key: "date_of_birth", Value: user.DateOfBirth},
			{Key: "agreement", Value: user.Agreement},
			{Key: "student_index", Value: user.StudentIndex},
			{Key: "occupation", Value: user.Occupation},
			{Key: "diet_preference", Value: user.DietPreference},
			{Key: "events", Value: user.Events},
		}},
		{Key: "$set", Value: bson.D{{Key: "verified", Value: true}}},
	}

	result, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		repo.logger.Error("Error updating user in database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))
		return model.User{}, err
	}
	if result.MatchedCount == 0 {
		repo.logger.Error("Cannot find following user in database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.String("email", user.Emails[0]),
			zap.String("token", token))
		return model.User{}, errors.New("user not found")
	}

	return user, nil
}

func (repo MongoRepository) AppendNotificationToUser(ctx context.Context, notification model.Notification) error {
	defer repo.logger.Sync()

	repo.logger.Debug("In AppendNotificationToUser method")

	coll := repo.client.Database(repo.database).Collection(NOTIFICATIONS_COLLECTION_NAME)

	_, err := coll.InsertOne(ctx, notification)
	if err != nil {
		repo.logger.Error("Error inserting notification into database",
			zap.String("database", repo.database),
			zap.String("collection", NOTIFICATIONS_COLLECTION_NAME),
			zap.Error(err))
	}

	return nil
}

func (repo MongoRepository) GetUserNotifications(ctx context.Context, userId string, service *string) ([]model.Notification, error) {
	defer repo.logger.Sync()

	repo.logger.Debug("In GetUserNotifications method")

	coll := repo.client.Database(repo.database).Collection(NOTIFICATIONS_COLLECTION_NAME)

	queryId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		repo.logger.Error("Cannot parse id to ObjectId",
			zap.String("database", repo.database),
			zap.String("collection", NOTIFICATIONS_COLLECTION_NAME),
			zap.String("id", userId),
			zap.Error(err))
	}

	filter := bson.D{{Key: "userId", Value: queryId}, {Key: "status", Value: "not-read"}}
	if *service != "" {
		filter = append(filter, bson.E{Key: "service", Value: *service})
	}

	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		repo.logger.Error("Error retreiving notifications from database",
			zap.String("database", repo.database),
			zap.String("collection", NOTIFICATIONS_COLLECTION_NAME),
			zap.Error(err))
		return []model.Notification{}, err
	}
	defer cursor.Close(ctx)
	var notifications []model.Notification

	for cursor.Next(ctx) {
		var notification model.Notification
		if err := cursor.Decode(&notification); err != nil {
			repo.logger.Error("Error decoding notification",
				zap.String("database", repo.database),
				zap.String("collection", NOTIFICATIONS_COLLECTION_NAME),
				zap.Error(err))
			return []model.Notification{}, err
		}
		notifications = append(notifications, notification)
	}
	if err := cursor.Err(); err != nil {
		repo.logger.Error("Error iterating over notifications",
			zap.String("database", repo.database),
			zap.String("collection", NOTIFICATIONS_COLLECTION_NAME),
			zap.Error(err))
		return []model.Notification{}, err
	}

	repo.logger.Info("Sucesfully retreive notifications from database")

	return notifications, nil
}

func (repo MongoRepository) ChangeNotificationStatus(ctx context.Context, userId string, notificationId string, status string) error {
	defer repo.logger.Sync()

	repo.logger.Debug("In ChangeNotificationStatus method")

	coll := repo.client.Database(repo.database).Collection(NOTIFICATIONS_COLLECTION_NAME)

	queryId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		repo.logger.Error("Cannot parse id to ObjectId",
			zap.String("database", repo.database),
			zap.String("collection", NOTIFICATIONS_COLLECTION_NAME),
			zap.String("id", userId),
			zap.Error(err))
	}

	notificationObjectId, err := primitive.ObjectIDFromHex(notificationId)
	if err != nil {
		repo.logger.Error("Cannot parse id to ObjectId",
			zap.String("database", repo.database),
			zap.String("collection", NOTIFICATIONS_COLLECTION_NAME),
			zap.String("id", notificationId),
			zap.Error(err))
	}

	filter := bson.D{{Key: "_id", Value: notificationObjectId}, {Key: "userId", Value: queryId}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "status", Value: status}}}}

	result, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		repo.logger.Error("Error updating notification in database",
			zap.String("database", repo.database),
			zap.String("collection", NOTIFICATIONS_COLLECTION_NAME),
			zap.Error(err))
		return err
	}
	if result.MatchedCount == 0 {
		repo.logger.Error("Cannot find following notification in database",
			zap.String("database", repo.database),
			zap.String("collection", NOTIFICATIONS_COLLECTION_NAME),
			zap.String("notificationId", notificationObjectId.String()),
			zap.Error(err))

		return errors.New("notification not found")
	}

	return nil
}

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
	AssignUserToEvent(ctx context.Context, id string, event string) error
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

func (repo MongoRepository) AssignUserToEvent(ctx context.Context, id string, event string) error {
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

	if result.MatchedCount == 0 {
		return errors.New("User already assigned to event")
	}

	repo.logger.Info("Successfully assigned event to user")
	return nil
}

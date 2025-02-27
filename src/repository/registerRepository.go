package repository

import (
	"context"
	"os"

	"INIT-SGGW/InIT-Azure-backend-01.Register/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
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
	collectionName := "Users"

	coll := repo.client.Database(repo.database).Collection(collectionName)

	result, err := coll.InsertOne(ctx, user)
	if err != nil {
		repo.logger.Error("Error inserting user into database",
			zap.Error(err))
		return err
	}

	repo.logger.Info("Sucesfully inserted user into database",
		zap.String("database", repo.database),
		zap.String("collection", collectionName),
		zap.Any("userId", result.InsertedID))

	return nil
}

func (repo MongoRepository) GetEmailByToken(ctx context.Context, verificationToken string) ([]string, error) {
	defer repo.logger.Sync()
	collectionName := "Users"

	repo.logger.Debug("In GetEmailByToken method")

	coll := repo.client.Database(repo.database).Collection(collectionName)

	filter := bson.D{{Key: "token", Value: verificationToken}}
	var dboUser model.User

	err := coll.FindOne(ctx, filter).Decode(&dboUser)
	if err == mongo.ErrNilDocument {
		repo.logger.Error("Cannot find following token in database",
			zap.String("database", repo.database),
			zap.String("collection", collectionName),
			zap.Error(err))

		return []string{}, err
	}
	if err != nil {
		repo.logger.Error("Error retreiving user from database",
			zap.String("database", repo.database),
			zap.String("collection", collectionName),
			zap.Error(err))
		return []string{}, err
	}

	return dboUser.Emails, err

}

func (repo MongoRepository) VerifyUser(ctx context.Context, email string) error {
	defer repo.logger.Sync()

	collectionName := "Users"

	repo.logger.Debug("In VerifyUser method")

	coll := repo.client.Database(repo.database).Collection(collectionName)

	filter := bson.D{{Key: "emails", Value: email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "verified", Value: true}}}}
	_, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		repo.logger.Error("Error updating record",
			zap.Error(err))
		return err
	}

	return nil

}

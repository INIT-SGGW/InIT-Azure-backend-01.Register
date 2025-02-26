package repository

import (
	"context"
	"os"

	"INIT-SGGW/InIT-Azure-backend-01.Register/model"

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

	coll := repo.client.Database(repo.database).Collection("Users")

	result, err := coll.InsertOne(ctx, user)
	if err != nil {
		repo.logger.Error("Error inserting user into database",
			zap.Error(err))
		return err
	}

	repo.logger.Info("Sucesfully inserted user into database",
		zap.String("database", repo.database),
		zap.String("collection", "Users"),
		zap.Any("userId", result.InsertedID))

	return nil
}

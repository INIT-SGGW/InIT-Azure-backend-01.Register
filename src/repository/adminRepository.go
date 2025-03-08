package repository

import (
	"context"

	"INIT-SGGW/InIT-Azure-backend-01.Register/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type AdminRepository interface {
	CreateAdminInDB(model.Admin, context.Context) error
	GetAdminEmailByToken(ctx context.Context, verificationToken string) (string, error)
	VerifyAdmin(ctx context.Context, email string) error
	GetAdminByEmail(ctx context.Context, email string) (model.Admin, error)
	GetAdminByID(ctx context.Context, id string) (model.Admin, error)
}

func (repo MongoRepository) CreateAdminInDB(admin model.Admin, ctx context.Context) error {
	defer repo.logger.Sync()

	repo.logger.Debug("In CreateAdminInDB method")

	coll := repo.client.Database(repo.database).Collection(ADMINS_COLLECTION_NAME)

	result, err := coll.InsertOne(ctx, admin)
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

	repo.logger.Info("Sucesfully inserted admin into database",
		zap.String("database", repo.database),
		zap.String("collection", ADMINS_COLLECTION_NAME),
		zap.Any("userId", result.InsertedID))

	return nil

}

func (repo MongoRepository) GetAdminEmailByToken(ctx context.Context, verificationToken string) (string, error) {
	defer repo.logger.Sync()

	repo.logger.Debug("In GetAdminEmailByToken method")

	coll := repo.client.Database(repo.database).Collection(ADMINS_COLLECTION_NAME)

	filter := bson.D{{Key: "verification_token", Value: verificationToken}}
	var dboAdmin model.Admin

	err := coll.FindOne(ctx, filter).Decode(&dboAdmin)
	if err == mongo.ErrNilDocument {
		repo.logger.Error("Cannot find following token in database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))

		return "", err
	}
	if err != nil {
		repo.logger.Error("Error retreiving user from database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))
		return "", err
	}
	repo.logger.Info("Sucesfully retreive admin from database",
		zap.String("collection", ADMINS_COLLECTION_NAME),
		zap.String("admin", dboAdmin.DiscordUsername))

	return dboAdmin.Email, err
}

func (repo MongoRepository) VerifyAdmin(ctx context.Context, email string) error {
	defer repo.logger.Sync()

	coll := repo.client.Database(repo.database).Collection(ADMINS_COLLECTION_NAME)

	filter := bson.D{{Key: "email", Value: email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "verified", Value: true}}}}
	_, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		repo.logger.Error("Error updating record",
			zap.String("collectionName", ADMINS_COLLECTION_NAME),
			zap.Error(err))
		return err
	}
	repo.logger.Info("Sucesfully verified admin",
		zap.String("collection", ADMINS_COLLECTION_NAME))

	return nil

}

func (repo MongoRepository) GetAdminByEmail(ctx context.Context, email string) (model.Admin, error) {
	defer repo.logger.Sync()

	_ = repo.client.Database(repo.database).Collection(ADMINS_COLLECTION_NAME)

	return model.Admin{}, nil

}
func (repo MongoRepository) GetAdminByID(ctx context.Context, id string) (model.Admin, error) {
	defer repo.logger.Sync()

	_ = repo.client.Database(repo.database).Collection(ADMINS_COLLECTION_NAME)

	return model.Admin{}, nil

}

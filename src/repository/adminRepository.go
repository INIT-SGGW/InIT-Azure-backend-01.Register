package repository

import (
	"context"
	"time"

	"INIT-SGGW/InIT-Azure-backend-01.Register/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type AdminRepository interface {
	CreateAdminInDB(model.Admin, context.Context) error
	GetAdminByToken(ctx context.Context, verificationToken string) (model.Admin, error)
	UpdateVerifyAdminData(ctx context.Context, adminDbo model.Admin) error
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

func (repo MongoRepository) GetAdminByToken(ctx context.Context, verificationToken string) (model.Admin, error) {
	defer repo.logger.Sync()

	repo.logger.Debug("In GetAdminByToken method")

	coll := repo.client.Database(repo.database).Collection(ADMINS_COLLECTION_NAME)

	filter := bson.D{{Key: "verification_token", Value: verificationToken}}
	var dboAdmin model.Admin

	err := coll.FindOne(ctx, filter).Decode(&dboAdmin)
	if err == mongo.ErrNilDocument {
		repo.logger.Error("Cannot find following token in database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))

		return model.Admin{}, err
	}
	if err != nil {
		repo.logger.Error("Error retreiving user from database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))
		return model.Admin{}, err
	}
	repo.logger.Info("Sucesfully retreive admin from database",
		zap.String("collection", ADMINS_COLLECTION_NAME),
		zap.String("admin", dboAdmin.DiscordUsername))

	return dboAdmin, err
}

func (repo MongoRepository) UpdateVerifyAdminData(ctx context.Context, adminDbo model.Admin) error {
	defer repo.logger.Sync()

	coll := repo.client.Database(repo.database).Collection(ADMINS_COLLECTION_NAME)

	repo.logger.Info("Sucesfully verified admin",
		zap.String("collection", ADMINS_COLLECTION_NAME),
		zap.String("adminUsername", adminDbo.DiscordUsername),
		zap.String("FirstName", adminDbo.FirstName),
		zap.String("LastName", adminDbo.LastName))

	filter := bson.D{{Key: "email", Value: adminDbo.Email}}
	update := bson.D{{Key: "$set", Value: bson.D{
		{Key: "verified", Value: true},
		{Key: "updated_at", Value: time.Now()},
		{Key: "first_name", Value: adminDbo.FirstName},
		{Key: "last_name", Value: adminDbo.LastName},
		{Key: "discord_username", Value: adminDbo.DiscordUsername},
		{Key: "password", Value: adminDbo.Password}}}} // Password is already hashed

	_, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		repo.logger.Error("Error updating record",
			zap.String("collectionName", ADMINS_COLLECTION_NAME),
			zap.String("adminusername", adminDbo.DiscordUsername),
			zap.Error(err))
		return err
	}
	repo.logger.Info("Sucesfully verified admin",
		zap.String("collection", ADMINS_COLLECTION_NAME),
		zap.String("adminUsername", adminDbo.DiscordUsername))

	return nil

}

func (repo MongoRepository) GetAdminByEmail(ctx context.Context, email string) (model.Admin, error) {
	defer repo.logger.Sync()

	repo.logger.Debug("In GetAdminByEmail method")

	coll := repo.client.Database(repo.database).Collection(ADMINS_COLLECTION_NAME)

	filter := bson.D{{Key: "email", Value: email}}
	var dboAdmin model.Admin

	err := coll.FindOne(ctx, filter).Decode(&dboAdmin)
	if err == mongo.ErrNilDocument {
		repo.logger.Error("Cannot find following admin in database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))

		return model.Admin{}, err
	}
	if err != nil {
		repo.logger.Error("Error retreiving admin from database",
			zap.String("database", repo.database),
			zap.String("collection", USER_COLLECTION_NAME),
			zap.Error(err))
		return model.Admin{}, err
	}
	repo.logger.Info("Sucesfully retreive admin from database",
		zap.String("database", repo.database),
		zap.String("collection", USER_COLLECTION_NAME))

	return dboAdmin, err

}
func (repo MongoRepository) GetAdminByID(ctx context.Context, id string) (model.Admin, error) {
	defer repo.logger.Sync()

	repo.logger.Debug("In GetAdminByID method")

	coll := repo.client.Database(repo.database).Collection(ADMINS_COLLECTION_NAME)
	queryId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		repo.logger.Error("Cannot parse id to ObjectId",
			zap.String("database", repo.database),
			zap.String("collection", ADMINS_COLLECTION_NAME),
			zap.String("id", id),
			zap.Error(err))
	}
	repo.logger.Info("Sucesfully parse id to ObjectId")

	filter := bson.D{{Key: "_id", Value: queryId}}
	var dboAdmin model.Admin

	err = coll.FindOne(ctx, filter).Decode(&dboAdmin)
	if err == mongo.ErrNilDocument {
		repo.logger.Error("Cannot find following user in database",
			zap.String("database", repo.database),
			zap.String("collection", ADMINS_COLLECTION_NAME),
			zap.String("id", queryId.String()),
			zap.Error(err))

		return model.Admin{}, err
	}
	if err != nil {
		repo.logger.Error("Error retreiving user from database",
			zap.String("database", repo.database),
			zap.String("collection", ADMINS_COLLECTION_NAME),
			zap.Error(err))
		return model.Admin{}, err
	}
	repo.logger.Info("Sucesfully retreive admin from database",
		zap.String("database", repo.database),
		zap.String("collection", ADMINS_COLLECTION_NAME),
		zap.String("id", queryId.String()))

	return dboAdmin, err

}

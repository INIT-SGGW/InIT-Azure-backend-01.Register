package repository

import (
	"context"

	"INIT-SGGW/InIT-Azure-backend-01.Register/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type EmailRepository interface {
	GetSingleTemplateByName(templateName string, ctx context.Context) (model.EmailTemplate, error)
}

func (repo MongoRepository) GetSingleTemplateByName(templateName string, ctx context.Context) (model.EmailTemplate, error) {
	defer repo.logger.Sync()

	coll := repo.client.Database(repo.database).Collection(EMAIL_TEMPLATE_COLLECTION_NAME)

	filter := bson.D{{Key: "template_name", Value: templateName}}
	var templ model.EmailTemplate

	err := coll.FindOne(ctx, filter).Decode(&templ)

	if err == mongo.ErrNilDocument {
		repo.logger.Error("Cannot find following template in database",
			zap.String("templateName", templateName),
			zap.String("database", repo.database),
			zap.String("collection", EMAIL_TEMPLATE_COLLECTION_NAME),
			zap.Error(err))

		return model.EmailTemplate{}, err
	}
	if err != nil {
		repo.logger.Error("Error retreiving template",
			zap.String("templateName", templateName),
			zap.String("database", repo.database),
			zap.String("collection", EMAIL_TEMPLATE_COLLECTION_NAME),
			zap.Error(err))
		return model.EmailTemplate{}, err
	}

	repo.logger.Info("Sucesfully retreive email template from database",
		zap.String("templateName", templateName),
		zap.String("database", repo.database),
		zap.String("collection", EMAIL_TEMPLATE_COLLECTION_NAME))

	return templ, err

}

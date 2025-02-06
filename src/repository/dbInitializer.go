package repository

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

func NewMongoClient(logger *zap.Logger, connectionString, dbname string) (mongoClient *mongo.Client, err error) {
	defer logger.Sync()

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(connectionString).SetServerAPIOptions(serverAPI)

	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		return nil, err
	}

	// ping database to confirm if application is alowed to connect
	err = testConnection(logger, client, dbname)
	if err != nil {
		logger.Error("Connection to database test fail",
			zap.String("database", dbname),
			zap.Error(err))
		return nil, err
	}
	return client, nil

}

func testConnection(logger *zap.Logger, client *mongo.Client, database string) error {
	defer logger.Sync()

	// Send a ping to confirm a successful connection
	if err := client.Database(database).RunCommand(context.TODO(), bson.D{{"ping", 1}}).Err(); err != nil {
		logger.Error("Cannot ping the database",
			zap.String("database", database))
		return err
	}
	logger.Info("Succesfully pinged your database",
		zap.String("database", database))

	return nil
}

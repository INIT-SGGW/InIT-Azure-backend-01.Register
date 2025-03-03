package initializer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func CreateLogger(logPath string) *zap.Logger {
	stdout := zapcore.AddSync(os.Stdout)

	level := zap.NewAtomicLevelAt(zap.InfoLevel)

	productionCfg := zap.NewProductionEncoderConfig()
	productionCfg.TimeKey = "timestamp"
	productionCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	developmentCfg := zap.NewDevelopmentEncoderConfig()
	developmentCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder

	consoleEncoder := zapcore.NewConsoleEncoder(developmentCfg)

	if logPath != " " {
		file := zapcore.AddSync(&lumberjack.Logger{
			Filename:   logPath,
			MaxSize:    10, // megabytes
			MaxBackups: 1,
			MaxAge:     3, // days
		})
		fileEncoder := zapcore.NewJSONEncoder(productionCfg)

		core := zapcore.NewTee(
			zapcore.NewCore(consoleEncoder, stdout, level),
			zapcore.NewCore(fileEncoder, file, level),
		)
		return zap.New(core)
	} else {
		core := zapcore.NewTee(zapcore.NewCore(consoleEncoder, stdout, level))
		return zap.New(core)
	}

}

func New(logger *zap.Logger) func(next http.Handler) http.Handler {
	defer logger.Sync()

	if logger == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			t1 := time.Now()
			defer func() {
				reqLogger := logger.With(
					zap.String("proto", r.Proto),
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
					zap.String("requestId", middleware.GetReqID(r.Context())),
					zap.Duration("latency", time.Since(t1)),
					zap.Int("status", ww.Status()),
					zap.Int("size", ww.BytesWritten()),
				)
				reqLogger.Info("Served")
			}()
			next.ServeHTTP(ww, r)
		}
		return http.HandlerFunc(fn)
	}

}

func AutorizeRequest(apiKey string, logger *zap.Logger) func(next http.Handler) http.Handler {
	if apiKey == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			defer logger.Sync()

			apiKeyHeader := "X-ICC-API-KEY"
			sendedApiKey := r.Header.Get(apiKeyHeader)
			if sendedApiKey == sendedApiKey {
				logger.Info("Valid API key")
				next.ServeHTTP(w, r)
			} else {
				logger.Error("Invalid request api key ")
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

		}
		return http.HandlerFunc(fn)
	}

}

func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		defer func() {
			err := recover()
			if err != nil {
				fmt.Println(err)

				jsonBody, _ := json.Marshal(map[string]string{
					"error": "There was an internal server error",
				})

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write(jsonBody)
			}

		}()

		next.ServeHTTP(w, r)

	})
}

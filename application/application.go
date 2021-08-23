package application

import (
	"fmt"
	"github.com/aerostatka/banking-auth/domain"
	"github.com/aerostatka/banking-auth/service"
	"github.com/aerostatka/banking-lib/logger"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
)

func Start() {
	sanityCheck()

	router := mux.NewRouter()
	dbClient := getDbClient()
	authRepositoryDb := domain.NewAuthRepositoryDb(dbClient)
	ah := AuthHandlers{service: service.CreateAuthService(authRepositoryDb, domain.GetRolePermissions())}
	router.HandleFunc("/auth/login", ah.Login).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.Verify).Methods(http.MethodGet)

	host := os.Getenv("SERVER_ADDRESS_AUTH")
	port := os.Getenv("SERVER_PORT_AUTH")

	logger.Info("Starting Oauth server.")
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), router))
}

func getDbClient() *sqlx.DB {
	dbHost := os.Getenv("DB_HOST_AUTH")
	dbPort := os.Getenv("DB_PORT_AUTH")
	dbUser := os.Getenv("DB_USER_AUTH")
	dbPassword := os.Getenv("DB_USER_AUTH")
	dbName := os.Getenv("DB_NAME_AUTH")
	client, err := sqlx.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName))
	if err != nil {
		panic(err)
	}

	// See "Important settings" section.
	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)

	return client
}

func sanityCheck() {
	if os.Getenv("SERVER_ADDRESS_AUTH") == "" ||
		os.Getenv("SERVER_PORT_AUTH") == "" {
		logger.Fatal("Server environment variables are not defined.")
	}

	if os.Getenv("DB_HOST_AUTH") == "" ||
		os.Getenv("DB_PORT_AUTH") == "" ||
		os.Getenv("DB_USER_AUTH") == "" ||
		os.Getenv("DB_USER_AUTH") == "" ||
		os.Getenv("DB_NAME_AUTH") == "" {
		logger.Fatal("DB environment variables are not defined.")
	}
}

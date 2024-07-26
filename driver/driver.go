package driver

import (
	//user defined package

	"echo/helper"
	logs "echo/log"
	"echo/repository"

	//built in package
	"fmt"
	"os"

	//third party package

	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func DatabaseConnection() error {
	log := logs.Logs()
	err := helper.Configure(".env")
	if err != nil {
		log.Error("error in loading env file")
		fmt.Println("error is loading env file ")
		return err
	}

	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	user := os.Getenv("DB_USER")

	//connecting to postgres-SQL
	connection := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)

	repository.Db, err = gorm.Open(postgres.Open(connection), &gorm.Config{})
	if err != nil {
		log.Error("error in connecting with database")
		fmt.Println("error in connecting with database")
		return err
	}

	log.Info("database connection sucessfull")
	fmt.Printf("%s,database connection sucessfull\n", dbname)
	return nil
}

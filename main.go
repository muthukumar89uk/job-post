package main

import (
	//user defined package
	_ "echo/docs"
	"echo/driver"
	logs "echo/log"
	"echo/repository"
	"echo/router"

	"github.com/labstack/echo/v4"
	echoSwagger "github.com/swaggo/echo-swagger"
)

// @title echo Example API
// @version 2.0
// @description This is a sample swagger for ECHO
// @termsOfService http://swagger.io/terms/
// @contact.name API Support
// @contact.email fiber@swagger.io
// @license.name Apache 2.0
// @consumes:application/json
// @produces:application/json
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8000
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @BasePath /api
func main() {
	log := logs.Logs()
	e := echo.New()

	if err := driver.DatabaseConnection(); err != nil {
		log.Error("failed to connecting the database")
		return
	}

	repository.CreateTables()

	router.Router(e)

	e.GET("/swagger/*", echoSwagger.WrapHandler)

	e.Logger.Fatal(e.Start(":8000"))
}

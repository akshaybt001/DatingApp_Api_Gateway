package initializer

import (
	"fmt"
	"os"

	notifycontrollers "github.com/akshaybt001/DatingApp_Api_Gateway/controllers/notifyControllers"
	usercontrollers "github.com/akshaybt001/DatingApp_Api_Gateway/controllers/userControllers"
	"github.com/akshaybt001/DatingApp_Api_Gateway/helper"
	"github.com/go-chi/chi"
	"github.com/joho/godotenv"
)

func Connect(r *chi.Mux) {
	if err := godotenv.Load("../.env"); err != nil {
		fmt.Println("error secret cannot be retreived")
	}
	sercet := os.Getenv("secret")
	userConn, err := helper.DialGrpc("localhost:8081")
	if err != nil {
		fmt.Println("cannot connet to user service", err)
	}
	notifyConn, err := helper.DialGrpc("localhost:8083")
	if err != nil {
		fmt.Println("connot connect to notification service", err)
	}
	userController := usercontrollers.NewUserServiceClient(userConn, sercet)
	notifyController :=notifycontrollers.NewNotificationServiceClient(notifyConn,sercet)

	userController.InitialiseUserControllers(r)
	notifyController.InitialiseNotifyControllers(r)
}

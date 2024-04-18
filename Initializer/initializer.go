package Initializer

import (
	"fmt"
	"os"

	usercontrollers "github.com/akshaybt001/DatingApp_Api_Gateway/controllers/userControllers"
	"github.com/akshaybt001/DatingApp_Api_Gateway/helper"
	"github.com/go-chi/chi"
	"github.com/joho/godotenv"
)

func Connect(r *chi.Mux){
	if err:=godotenv.Load("../.env");err!=nil{
		fmt.Println("error secret cannot be retreived")
	}
	sercet:=os.Getenv("secret")
	userConn,err:=helper.DialGrpc("user-service:8081")
	if err!=nil{
		fmt.Println("cannot connet to user-service",err)
	}
	userController:=usercontrollers.NewUserServiceClient(userConn,sercet)

	userController.InitialiseUserControllers(r)
}
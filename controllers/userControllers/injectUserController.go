package usercontrollers

import (
	"github.com/akshaybt001/DatingApp_proto_files/pb"
	"github.com/go-chi/chi"
	"google.golang.org/grpc"
)

type UserController struct {
	UserConn pb.UserServiceClient
	Secret string
}

func NewUserServiceClient(conn *grpc.ClientConn,secret string)*UserController{
	return &UserController{
		UserConn: pb.NewUserServiceClient(conn),
		Secret: secret,
	}
}

func (user *UserController) InitialiseUserControllers(r *chi.Mux){

}
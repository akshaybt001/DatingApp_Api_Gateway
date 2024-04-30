package usercontrollers

import (
	"github.com/akshaybt001/DatingApp_Api_Gateway/helper"
	"github.com/akshaybt001/DatingApp_Api_Gateway/middleware"
	"github.com/akshaybt001/DatingApp_proto_files/pb"
	"github.com/go-chi/chi"
	"google.golang.org/grpc"
)

type UserController struct {
	UserConn    pb.UserServiceClient
	NotifiyConn pb.NotificationClient
	Secret      string
}

func NewUserServiceClient(conn *grpc.ClientConn, secret string) *UserController {
	notifiyConn, _ := helper.DialGrpc("localhost:8083")
	return &UserController{
		UserConn:    pb.NewUserServiceClient(conn),
		NotifiyConn: pb.NewNotificationClient(notifiyConn),
		Secret:      secret,
	}
}

func (user *UserController) InitialiseUserControllers(r *chi.Mux) {
	r.Post("/user/signup", user.userSignup)
	r.Post("/user/login", user.userLogin)
	r.Post("/user/logout", middleware.UserMiddleware(user.userdLogout))

	r.Post("/user/profile/address", middleware.UserMiddleware(user.addAddress))
	r.Patch("/user/profile/address", middleware.UserMiddleware(user.editAddress))
	r.Get("/user/profile/address", middleware.UserMiddleware(user.getAddress))
	r.Get("/user/interests", middleware.UserMiddleware(user.getAllInterestUser))
	r.Post("/user/interest/add", middleware.UserMiddleware(user.addInterestUser))
	r.Delete("/user/interest", middleware.UserMiddleware(user.DeleteInterestUser))
	r.Post("/user/gender", middleware.UserMiddleware(user.addGenderUser))
	r.Get("/user/gender", middleware.UserMiddleware(user.getGenderUser))
	r.Post("/user/profile/preference", middleware.UserMiddleware(user.addPreference))
	r.Patch("/user/profile/preference", middleware.UserMiddleware(user.editPreference))
	r.Get("/user/profile/preference", middleware.UserMiddleware(user.getPreference))
	r.Post("/user/profile/image", middleware.UserMiddleware(user.uploadProfilePic))
	r.Get("/user/profile", middleware.UserMiddleware(user.getProfile))

	r.Post("/admin/login", user.adminLogin)
	r.Post("/admin/logout", middleware.AdminMiddleware(user.adminLogout))
	r.Post("/admin/interest", middleware.AdminMiddleware(user.adminAddInterest))
	r.Patch("/admin/interest", middleware.AdminMiddleware(user.adminUpdateInterest))
	r.Get("/interest", user.GetAllInterest)
	r.Post("/admin/gender", middleware.AdminMiddleware(user.adminAddGender))
	r.Patch("/admin/gender", middleware.AdminMiddleware(user.adminUpdateGender))
	r.Get("/admin/gender", middleware.AdminMiddleware(user.getAllGenders))

}

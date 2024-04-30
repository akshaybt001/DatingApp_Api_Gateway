package notifycontrollers

import (
	"github.com/akshaybt001/DatingApp_proto_files/pb"
	"github.com/go-chi/chi"
	"google.golang.org/grpc"
)

type NotifyController struct {
	Conn pb.NotificationClient
	Secret string
}

func NewNotificationServiceClient(conn *grpc.ClientConn,Secret string) *NotifyController{
	return &NotifyController{
		Conn: pb.NewNotificationClient(conn),
		Secret: Secret,
	}
}

func (notify *NotifyController) InitialiseNotifyControllers(r *chi.Mux){
	
}
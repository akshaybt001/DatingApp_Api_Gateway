package matchcontrollers

import (
	"github.com/akshaybt001/DatingApp_Api_Gateway/middleware"
	"github.com/akshaybt001/DatingApp_proto_files/pb"
	"github.com/go-chi/chi"
	"google.golang.org/grpc"
)

type MatchController struct {
	MatchConn pb.MatchServiceClient
}

func NewMatchServiceClient(conn *grpc.ClientConn) *MatchController {
	return &MatchController{
		MatchConn: pb.NewMatchServiceClient(conn),
	}
}

func (m *MatchController) InitialiseUserControllers(r *chi.Mux) {
	r.Post("/like", middleware.UserMiddleware(m.like))
	r.Get("/match", middleware.UserMiddleware(m.getMatch))
	r.Delete("/match", middleware.UserMiddleware(m.deleteMatch))
	r.Get("/like/view", middleware.UserMiddleware(m.getWhoLikeUser))
}

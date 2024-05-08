package matchcontrollers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/akshaybt001/DatingApp_Api_Gateway/helper"
	"github.com/akshaybt001/DatingApp_proto_files/pb"
)

func (m *MatchController) like(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving id", http.StatusBadRequest)
		return
	}
	req := &pb.LikeRequest{
		UserId: userID,
	}
	queryParam := r.URL.Query()
	req.LikedId = queryParam.Get("likedId")
	if _, err := m.MatchConn.Like(context.Background(), req); err != nil {
		helper.PrintError("error while liking user", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "liked successfully"}`))
}

func (m *MatchController) getMatch(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving id", http.StatusBadRequest)
		return
	}
	req := &pb.GetByUserId{
		Id: userID,
	}
	matches, err := m.MatchConn.GetMatch(context.Background(), req)
	if err != nil {
		helper.PrintError("error while listing matches", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	matchData := []*pb.MatchResposne{}
	for {
		match, err := matches.Recv()

		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving stream", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		matchData = append(matchData, match)
	}
	jsonData, err := json.Marshal(matchData)
	if err != nil {
		helper.PrintError("error while marshalling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(matchData) == 0 {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"no matches added"}`))
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func (m *MatchController) deleteMatch(w http.ResponseWriter, r *http.Request) {

	queryParam := r.URL.Query()
	id := queryParam.Get("matchId")
	req := &pb.GetByUserId{
		Id: id,
	}
	if _, err := m.MatchConn.UnMatch(context.Background(), req); err != nil {
		helper.PrintError("error while deleteing match id", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "deleted successfully"}`))
}


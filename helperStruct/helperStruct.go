package helperstruct

import "github.com/akshaybt001/DatingApp_proto_files/pb"

type UserProfile struct {
	Id         string                 `json:"id,omitempty"`
	Name       string                 `json:"name,omitempty"`
	Email      string                 `json:"email,omitempty"`
	Phone      string                 `json:"phone,omitempty"`
	Image      string                 `json:"image,omitempty"`
	Gender     *pb.GenderResponse     `json:"gender,omitempty"`
	Interest   []*pb.InterestResponse `json:"interest,omitempty"`
	Preference *pb.PreferenceResponse `json:"preference,omitempty"`
	Address    *pb.AddressResponse    `json:"address,omitempty"`
}

package notifycontrollers

import (
	"context"

	"github.com/akshaybt001/DatingApp_proto_files/pb"
)

func (n *NotifyController) SendOTP(email string) error {
	_, err := n.Conn.SendOTP(context.Background(), &pb.SendOtpRequest{
		Email: email,
	})
	return err
}

func (n *NotifyController) VerifyOTP(email string, otp string) bool {
	res, err := n.Conn.VerifyOTP(context.Background(), &pb.VerifyOtpRequest{
		Otp:   otp,
		Email: email,
	})
	if err != nil {
		return false
	}
	return res.Verified
}

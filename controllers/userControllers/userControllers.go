package usercontrollers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/akshaybt001/DatingApp_Api_Gateway/JWT"
	"github.com/akshaybt001/DatingApp_Api_Gateway/helper"
	helperstruct "github.com/akshaybt001/DatingApp_Api_Gateway/helperStruct"
	"github.com/akshaybt001/DatingApp_proto_files/pb"
)

func (user *UserController) userSignup(w http.ResponseWriter, r *http.Request) {
	if cookie, _ := r.Cookie("UserToken"); cookie != nil {
		http.Error(w, "you are already logged in ..", http.StatusConflict)
		return
	}
	var req pb.UserSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Email == "" {
		http.Error(w, "please enter a valid email", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Name) {
		http.Error(w, "please enter a valid name without a number", http.StatusBadRequest)
	}
	if !helper.ValidEmail(req.Email) {
		http.Error(w, "please enter a valid email", http.StatusBadRequest)
		return
	}
	if !helper.CheckStringNumber(req.Phone) {
		http.Error(w, "please enter a valid phone number ", http.StatusBadRequest)
		return
	}
	if !helper.IsStrongPassword(req.Password) {
		http.Error(w, "please enter a strong password which contains lowercase,uppercase,number and atleast 1 special character", http.StatusBadRequest)
		return
	}

	if req.Otp == "" {
		_, err := user.NotifiyConn.SendOTP(context.Background(), &pb.SendOtpRequest{
			Email: req.Email,
		})
		if err != nil {
			helper.PrintError("error sending otp", err)
			http.Error(w, "error sending otp", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"message": "please enter the OTP sent to your email"})
		return

	} else {
		varifyotp, err := user.NotifiyConn.VerifyOTP(context.Background(), &pb.VerifyOtpRequest{
			Otp:   req.Otp,
			Email: req.Email,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

		}
		if !varifyotp.Verified {
			http.Error(w, "otp verification failed please try again", http.StatusBadRequest)
			return
		}
	}
	res, err := user.UserConn.UserSignup(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := user.UserConn.CreateProfile(context.Background(), &pb.GetUserById{
		Id: res.Id,
	}); err != nil {
		helper.PrintError("error while creating profile", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookieString, err := JWT.GenerateJWT(res.Id, false, []byte(user.Secret))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	cookie := &http.Cookie{
		Name:     "UserToken",
		Value:    cookieString,
		Expires:  time.Now().Add(48 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusCreated)

	w.Header().Set("Content-Type", "application/json")

	w.Write(jsonData)

}
func (user *UserController) userLogin(w http.ResponseWriter, r *http.Request) {
	if cookie, _ := r.Cookie("UserToken"); cookie != nil {
		http.Error(w, "you are already logged in..", http.StatusConflict)
		return
	}
	var req *pb.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := user.UserConn.UserLogin(context.Background(), req)
	if err != nil {
		helper.PrintError("error while logging in", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cookieString, err := JWT.GenerateJWT(res.Id, false, []byte(user.Secret))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	cookie := &http.Cookie{
		Name:     "UserToken",
		Value:    cookieString,
		Expires:  time.Now().Add(48 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func (user *UserController) adminLogin(w http.ResponseWriter, r *http.Request) {
	if cookie, _ := r.Cookie("AdminToken"); cookie != nil {
		http.Error(w, "you are already logging in ...", http.StatusConflict)
	}
	var req *pb.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json body ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := user.UserConn.AdminLogin(context.Background(), req)
	if err != nil {
		helper.PrintError("error while logging in", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		helper.PrintError("error while converting to json ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookieString, err := JWT.GenerateJWT(res.Id, true, []byte(user.Secret))
	if err != nil {
		helper.PrintError("error while generaing jwt", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:     "AdminToken",
		Value:    cookieString,
		Path:     "/",
		Expires:  time.Now().Add(48 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func (user *UserController) userdLogout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "UserToken",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"Logged out successfully"}`))
}

func (user *UserController) adminLogout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "AdminToken",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"Logged out successfully"}`))
}

func (user *UserController) adminAddInterest(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddInterestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Interest) {
		http.Error(w, "please enter a valid interest name", http.StatusBadRequest)
		return
	}
	if _, err := user.UserConn.AdminAddInterest(context.Background(), req); err != nil {
		helper.PrintError("error while adding interest", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "added successfully"}`))
}

func (user *UserController) adminUpdateInterest(w http.ResponseWriter, r *http.Request) {
	var req *pb.InterestResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Interest) {
		http.Error(w, "please enter a valid interest", http.StatusBadRequest)
		return
	}
	queryParams := r.URL.Query()
	interestID, err := strconv.Atoi(queryParams.Get("interest_id"))
	if err != nil {
		helper.PrintError("error while converting id to string", err)
		http.Error(w, "error while parsing the interest id to int", http.StatusBadRequest)
		return
	}
	req.Id = int32(interestID)
	if _, err := user.UserConn.AdminUpdateInterest(context.Background(), req); err != nil {
		helper.PrintError("error while updating interest", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "updated successfully"}`))
}

func (user *UserController) GetAllInterest(w http.ResponseWriter, r *http.Request) {
	interests, err := user.UserConn.GetAllInterest(context.Background(), nil)
	if err != nil {
		helper.PrintError("error while retrieving all interest", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	interestData := []*pb.InterestResponse{}
	for {
		interest, err := interests.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving interests", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		interestData = append(interestData, interest)
	}
	jsonData, err := json.Marshal(interestData)
	if err != nil {
		helper.PrintError("error while marshaling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func (user *UserController) addInterestUser(w http.ResponseWriter, r *http.Request) {
	var req *pb.DeleteInterestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving id", http.StatusBadRequest)
		return
	}
	req.UserId = userID

	if _, err := user.UserConn.AddInterestUser(context.Background(), req); err != nil {
		helper.PrintError("error while adding interest user", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "added successfully"}`))
}

func (user *UserController) DeleteInterestUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving id", http.StatusBadRequest)
		return
	}
	req := &pb.DeleteInterestRequest{
		UserId: userID,
	}
	queryParam := r.URL.Query()
	interestID, err := strconv.Atoi(queryParam.Get("interest_id"))
	if err != nil {
		helper.PrintError("error while converting id to string", err)
		http.Error(w, "error while parsing the id to int", http.StatusBadRequest)
		return
	}
	req.InterestId = int32(interestID)
	if _, err := user.UserConn.DeleteInterestUser(context.Background(), req); err != nil {
		helper.PrintError("error while deleting interest user", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "deleted successfully"}`))
}

func (user *UserController) getAllInterestUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving id", http.StatusBadRequest)
		return
	}
	req := &pb.GetUserById{
		Id: userID,
	}
	interests, err := user.UserConn.GetAllInterestsUser(context.Background(), req)
	if err != nil {
		helper.PrintError("error while listing interests", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	interestsData := []*pb.InterestResponse{}
	for {
		interest, err := interests.Recv()

		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving stream", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		interestsData = append(interestsData, interest)
	}
	jsonData, err := json.Marshal(interestsData)
	if err != nil {
		helper.PrintError("error while marshalling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(interestsData) == 0 {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"no interests added"}`))
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)

}

func (user *UserController) addAddress(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
		http.Error(w, "error parsing json", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Country) {
		http.Error(w, "please provide a valid country name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.State) {
		http.Error(w, "please provide a valid State name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.District) {
		http.Error(w, "please provide a valid District name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.City) {
		http.Error(w, "please provide a valid City name", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.UserConn.UserAddAddress(context.Background(), req); err != nil {
		helper.PrintError("error while adding address", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "added successfully"}`))
}

func (user *UserController) editAddress(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddressResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
		http.Error(w, "error parsing json", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Country) {
		http.Error(w, "please provide a valid country name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.State) {
		http.Error(w, "please provide a valid State name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.District) {
		http.Error(w, "please provide a valid District name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.City) {
		http.Error(w, "please provide a valid City name", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving Id", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.UserConn.UserEditAddress(context.Background(), req); err != nil {
		helper.PrintError("error while updating address", err)
		http.Error(w, "error while updating address", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "updated successfully"}`))
}

func (user *UserController) getAddress(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving Id", http.StatusBadRequest)
		return
	}
	req := &pb.GetUserById{
		Id: userID,
	}
	address, err := user.UserConn.UserGetAddress(context.Background(), req)
	if err != nil {
		helper.PrintError("error while retrieving address", err)
		http.Error(w, "error while retrieving address", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if address.Country == "" {
		w.Write([]byte(`{"message":"please add address"}`))
		return
	}
	jsonData, err := json.Marshal(address)
	if err != nil {
		helper.PrintError("error marshalling to json", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(jsonData)

}

func (user *UserController) adminAddGender(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddGenderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Gender) {
		http.Error(w, "please enter a valie gender name", http.StatusBadRequest)
		return
	}
	if _, err := user.UserConn.AdminAddGender(context.Background(), req); err != nil {
		helper.PrintError("error while adding gender", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "added successfully"}`))
}

func (user *UserController) adminUpdateGender(w http.ResponseWriter, r *http.Request) {
	var req *pb.GenderResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Gender) {
		http.Error(w, "please enter a valid gender ", http.StatusBadRequest)
		return
	}
	queryParams := r.URL.Query()
	genderID, err := strconv.Atoi(queryParams.Get("gender_id"))
	if err != nil {
		helper.PrintError("error while converting id to string", err)
		http.Error(w, "error while parsing the gender id to int", http.StatusBadRequest)
		return
	}
	req.Id = int32(genderID)
	if _, err := user.UserConn.AdminUpdateGender(context.Background(), req); err != nil {
		helper.PrintError("error while updating gender", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "updated successfully"}`))
}

func (user *UserController) getAllGenders(w http.ResponseWriter, r *http.Request) {
	genders, err := user.UserConn.GetAllGender(context.Background(), nil)
	if err != nil {
		helper.PrintError("error while retrieving all genders", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	gendersData := []*pb.GenderResponse{}
	for {
		gender, err := genders.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving genders", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gendersData = append(gendersData, gender)
	}
	jsonData, err := json.Marshal(gendersData)
	if err != nil {
		helper.PrintError("error while marshaling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func (user *UserController) addGenderUser(w http.ResponseWriter, r *http.Request) {
	var req *pb.UpdateGenderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving id", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.UserConn.AddGenderUser(context.Background(), req); err != nil {
		helper.PrintError("error while adding gender user", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "added successfully"}`))
}

// func (user *UserController) getGenderUser(w http.ResponseWriter, r *http.Request) {
// 	userID, ok := r.Context().Value("userId").(string)
// 	if !ok {
// 		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
// 		http.Error(w, "error while retrieving id", http.StatusBadRequest)
// 		return
// 	}
// 	req := &pb.GetUserById{
// 		Id: userID,
// 	}
// 	genders, err := user.UserConn.GetAllGenderUser(context.Background(), req)
// 	if err != nil {
// 		helper.PrintError("error while listing gender", err)
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}
// 	genderData := []*pb.GenderResponse{}
// 	for {
// 		gender, err := genders.Recv()
// 		if err == io.EOF {
// 			break
// 		}
// 		if err != nil {
// 			helper.PrintError("error while recieving stream", err)
// 			http.Error(w, err.Error(), http.StatusBadRequest)
// 			return
// 		}
// 		genderData = append(genderData, gender)
// 	}
// 	jsonData, err := json.Marshal(genderData)
// 	if err != nil {
// 		helper.PrintError("error while marshalling to json", err)
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}
// 	if len(genderData) == 0 {
// 		w.WriteHeader(http.StatusOK)
// 		w.Header().Set("Content-Type", "application/json")
// 		w.Write([]byte(`{"message":"no gender added"}`))
// 	}
// 	w.WriteHeader(http.StatusOK)
// 	w.Header().Set("Content-Type", "application/json")
// 	w.Write(jsonData)

// }
func (user *UserController) getGenderUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving Id", http.StatusBadRequest)
		return
	}
	req := &pb.GetUserById{
		Id: userID,
	}
	gender, err := user.UserConn.GetAllGenderUser(context.Background(), req)
	if err != nil {
		helper.PrintError("error while retrieving gender", err)
		http.Error(w, "error while retrieving gender", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if gender.Gender == "" {
		w.Write([]byte(`{"message":"please add gender"}`))
		return
	}
	jsonData, err := json.Marshal(gender)
	if err != nil {
		helper.PrintError("error marshalling to json", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(jsonData)

}

func (user *UserController) addPreference(w http.ResponseWriter, r *http.Request) {
	var req *pb.PreferenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
		http.Error(w, "error parsing json", http.StatusBadRequest)
		return
	}
	if !helper.ContainsOnlyNumbers(int(req.Minage)) {
		http.Error(w, "please provide a valid minage ", http.StatusBadRequest)
		return
	}
	if !helper.ContainsOnlyNumbers(int(req.Maxage)) {
		http.Error(w, "please provide a valid maxage ", http.StatusBadRequest)
		return
	}
	if !helper.ContainsOnlyThis(int(req.Gender)) {
		http.Error(w, "please provide a valid gender ", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Desirecity) {
		http.Error(w, "please provide a valid desired city name", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.UserConn.UserAddPreference(context.Background(), req); err != nil {
		helper.PrintError("error while adding Preference", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "added successfully"}`))
}

func (user *UserController) editPreference(w http.ResponseWriter, r *http.Request) {
	var req *pb.PreferenceResponse

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
		http.Error(w, "error parsing json", http.StatusBadRequest)
		return
	}
	if !helper.ContainsOnlyNumbers(int(req.Minage)) {
		http.Error(w, "please provide a valid minage ", http.StatusBadRequest)
		return
	}
	if !helper.ContainsOnlyNumbers(int(req.Maxage)) {
		http.Error(w, "please provide a valid maxage ", http.StatusBadRequest)
		return
	}
	if !helper.ContainsOnlyThis(int(req.Gender)) {
		http.Error(w, "please provide a valid gender ", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Desirecity) {
		http.Error(w, "please provide a valid desired city name", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.UserConn.UserEditPreference(context.Background(), req); err != nil {
		helper.PrintError("error while updating Preference", err)
		http.Error(w, "error while updating Preference", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "updated successfully"}`))
}

func (user *UserController) getPreference(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving Id", http.StatusBadRequest)
		return
	}
	req := &pb.GetUserById{
		Id: userID,
	}
	preference, err := user.UserConn.GetAllPreference(context.Background(), req)
	if err != nil {
		helper.PrintError("error while retrieving address", err)
		http.Error(w, "error while retrieving address", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if preference.Desirecity == "" {
		w.Write([]byte(`{"message":"please add preference"}`))
		return
	}
	jsonData, err := json.Marshal(preference)
	if err != nil {
		helper.PrintError("error marshalling to json", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(jsonData)
}
func (user *UserController) uploadProfilePic(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "unable to parse form", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "unable to get file from request", http.StatusBadRequest)
		return
	}
	defer file.Close()
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "error reading file", http.StatusInternalServerError)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving Id", http.StatusBadRequest)
		return
	}
	req := &pb.UserImageRequest{
		ObjectName: fmt.Sprintf("%s-profile", userID),
		ImageData:  fileBytes,
		UserId:     userID,
	}
	res, err := user.UserConn.UserUploadProfileImage(context.Background(), req)
	if err != nil {
		http.Error(w, "error while uploading image", http.StatusBadRequest)
		fmt.Println("here", err)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		http.Error(w, "error while marshalling to json", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func (user *UserController) getProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving Id", http.StatusBadRequest)
		return
	}
	userData, err := user.UserConn.GetUser(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		helper.PrintError("error retrieving user", err)
		http.Error(w, "error retrieving user info", http.StatusBadRequest)
		return
	}
	interests, err := user.UserConn.GetAllInterestsUser(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	interestData := []*pb.InterestResponse{}
	for {
		interest, err := interests.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		interestData = append(interestData, interest)
	}
	address, err := user.UserConn.UserGetAddress(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	genderData, err := user.UserConn.GetAllGenderUser(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	preferenceData, err := user.UserConn.GetAllPreference(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	imageData, err := user.UserConn.UserGetProfilePic(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res := helperstruct.UserProfile{
		Id:         userData.Id,
		Name:       userData.Name,
		Email:      userData.Email,
		Phone:      userData.Phone,
		Image:      imageData.Url,
		Gender:     genderData,
		Address:    address,
		Interest:   interestData,
		Preference: preferenceData,
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

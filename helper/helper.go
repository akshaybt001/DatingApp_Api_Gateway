package helper

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"google.golang.org/grpc"
)

func DialGrpc(addr string) (*grpc.ClientConn, error) {
	return grpc.Dial(addr, grpc.WithInsecure())
}

func CheckString(s string) bool {
	for _, str := range s {
		if unicode.IsNumber(str) {
			return false
		}
	}
	if len(s) == 0 {
		return false
	}
	return true
}

func PrintError(message string, err error) {
	fmt.Println(message, " ", err.Error())
}

func ContainsOnlyNumbers(input int) bool {
    inputStr := strconv.Itoa(input) 
    for _, char := range inputStr {
        if char < '0' || char > '9' {
            return false
        }
    }
    return true
}

func ContainsOnlyThis(input int)bool{
	if input==1 || input==2{
		return true
	}
	return false
}

func CheckStringNumber(s string) bool {
	_, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return len(s) == 10
}

func ValidEmail(s string) bool {
	if strings.Contains(s, "@") {
		return true
	}
	return false
}

func IsStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}

	}
	return hasUpper && hasLower && hasNumber && hasSpecial
}

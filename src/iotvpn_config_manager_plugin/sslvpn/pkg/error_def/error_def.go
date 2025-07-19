package errors

import "fmt"

//api 接口返回json中的错误码定义

var (
	ErrOk               = 0
	ErrInvalidParam     = -1
	ErrInternal         = -2
	ErrNotFound         = -3
	ErrAlreadyExists    = -4
	ErrPermissionDenied = -5
	ErrUnauthorized     = -6
	ErrForbidden        = -7
	ErrBadRequest       = -8
	ErrInvalidCert      = -9
	ErrInvalidKey       = -10
	ErrInvalidCA        = -11
	ErrInvalidDH        = -12
	ErrInvalidTLSAuth   = -13
	ErrInvalidCRL       = -14
)

func GetErrDesc(code int, customMsg string) string {
	if code == ErrOk {
		return "success"
	}

	retMsg := ""

	switch code {
	case ErrOk:
		retMsg = "success"
	case ErrInvalidParam:
		retMsg = "invalid parameter"
	case ErrInternal:
		retMsg = "internal error"
	case ErrNotFound:
		retMsg = "not found"
	case ErrAlreadyExists:
		retMsg = "already exists"
	case ErrPermissionDenied:
		retMsg = "permission denied"
	case ErrUnauthorized:
		retMsg = "unauthorized"
	case ErrForbidden:
		retMsg = "forbidden"
	case ErrBadRequest:
		retMsg = "bad request"
	default:
		retMsg = "unknown error"
	}

	retMsg = fmt.Sprintf("code:%d ,msg:%s", code, retMsg)

	if customMsg != "" {
		retMsg = retMsg + " ," + customMsg
	}

	return retMsg
}

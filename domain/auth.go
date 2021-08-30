package domain

import "github.com/aerostatka/banking-lib/errs"

type AuthRepository interface {
	FindBy(string, string) (*Login, *errs.AppError)
}

type AuthorizationRequest struct {
	IsAuthorized bool   `json:"isAuthorized"`
	Message      string `json:"message,omitempty"`
}

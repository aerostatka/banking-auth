package domain

import "github.com/aerostatka/banking-lib/errs"

type AuthRepository interface {
	FindBy(user string, pass string) (*Login, *errs.AppError)
	GenerateAndSaveRefreshToken(authToken *AuthToken) (string, *errs.AppError)
}

type AuthorizationRequest struct {
	IsAuthorized bool   `json:"isAuthorized"`
	Message      string `json:"message,omitempty"`
}

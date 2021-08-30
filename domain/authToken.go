package domain

import (
	"github.com/aerostatka/banking-lib/errs"
	"github.com/aerostatka/banking-lib/logger"
	"github.com/golang-jwt/jwt"
)

type AuthToken struct {
	token *jwt.Token
}

func (authToken *AuthToken) NewAccessToken() (string, *errs.AppError) {
	signedToken, err := authToken.token.SignedString([]byte(HMAC_SAMPLE_SECRET))

	if err != nil {
		logger.Error("Failed while signing token" + err.Error())

		return "", errs.NewInternalServerError("Error during token generation")
	}

	return signedToken, nil
}

func (authToken *AuthToken) newRefreshToken() (string, *errs.AppError) {
	claims := authToken.token.Claims.(Claims)
	refreshClaims := (&claims).RefreshTokenClaims()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedToken, err := token.SignedString([]byte(HMAC_SAMPLE_SECRET))

	if err != nil {
		logger.Error("Failed while signing refresh token" + err.Error())

		return "", errs.NewInternalServerError("Error during token generation")
	}

	return signedToken, nil
}

func NewAuthToken(claims Claims) *AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return &AuthToken{
		token: token,
	}
}

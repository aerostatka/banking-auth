package domain

import (
	"database/sql"
	"github.com/aerostatka/banking-lib/errs"
	"github.com/aerostatka/banking-lib/logger"
	"github.com/golang-jwt/jwt"
	"strings"
	"time"
)

const TOKEN_DURATION = time.Hour

type Login struct {
	Username   string         `db:"username"`
	CustomerId sql.NullString `db:"customer_id"`
	Accounts   sql.NullString `db:"account_numbers"`
	Role       string         `db:"role"`
}

func (l *Login) GenerateToken() (*string, *errs.AppError) {
	var claims jwt.MapClaims

	if l.Accounts.Valid && l.CustomerId.Valid {
		claims = l.claimsForUser()
	} else {
		claims = l.claimsForAdmin()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(HMAC_SAMPLE_SECRET))

	if err != nil {
		logger.Error("Failed while signing token" + err.Error())

		return nil, errs.NewInternalServerError("Error during token generation")
	}

	return &signedToken, nil
}

func (l *Login) claimsForUser() jwt.MapClaims {
	accounts := strings.Split(l.Accounts.String, ",")

	return jwt.MapClaims{
		"customer_id": l.CustomerId.String,
		"role":        l.Role,
		"username":    l.Username,
		"accounts":    accounts,
		"exp":         time.Now().Add(TOKEN_DURATION).Unix(),
	}
}

func (l *Login) claimsForAdmin() jwt.MapClaims {
	return jwt.MapClaims{
		"role":     l.Role,
		"username": l.Username,
		"exp":      time.Now().Add(TOKEN_DURATION).Unix(),
	}
}
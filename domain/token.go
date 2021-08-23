package domain

import (
	"encoding/json"
	"github.com/aerostatka/banking-lib/errs"
	"github.com/golang-jwt/jwt"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"

type Claims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	Expiry     int      `json:"exp"`
	Role       string   `json:"role"`
}

func (c *Claims) IsUserRole() bool {
	return c.Role == "user"
}

func (c *Claims) IsRequestVerifiedWithTokenClaims(params map[string]string) bool {
	if c.CustomerId != params["customerId"] {
		return false
	}

	if !c.IsValidAccountId(params["accountId"]) {
		return false
	}

	return true
}

func (c *Claims) IsValidAccountId(accId string) bool {
	if accId == "" {
		return true
	}

	for _, v := range c.Accounts {
		if v == accId {
			return true
		}
	}

	return false
}

func BuildClaimsFromJwtMapClaims(mapClaims jwt.MapClaims) (*Claims, *errs.AppError) {
	bytes, err := json.Marshal(mapClaims)
	var c Claims

	if err != nil {
		return nil, errs.NewInternalServerError("Token cannot be parsed")
	}

	err = json.Unmarshal(bytes, &c)

	if err != nil {
		return nil, errs.NewInternalServerError("Unable to unmarshall claims")
	}

	return &c, nil
}

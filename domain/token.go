package domain

import (
	"github.com/golang-jwt/jwt"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"

type Claims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	jwt.StandardClaims
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

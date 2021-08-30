package domain

import (
	"github.com/golang-jwt/jwt"
	"time"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"
const TOKEN_DURATION = time.Hour
const REFRESH_TOKEN_DURATION = time.Hour * 24 * 30

type Claims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	jwt.StandardClaims
}

type RefreshTokenClams struct {
	TokenType  string   `json:"token_type"`
	CustomerId string   `json:"cid"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"un"`
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

func (c *Claims) RefreshTokenClaims() RefreshTokenClams {
	return RefreshTokenClams{
		TokenType:  "refresh_token",
		CustomerId: c.CustomerId,
		Accounts:   c.Accounts,
		Username:   c.Username,
		Role:       c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(REFRESH_TOKEN_DURATION).Unix(),
		},
	}
}

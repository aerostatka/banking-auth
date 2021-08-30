package service

import (
	"fmt"
	"github.com/aerostatka/banking-auth/domain"
	"github.com/aerostatka/banking-auth/dto"
	"github.com/aerostatka/banking-lib/errs"
	"github.com/aerostatka/banking-lib/logger"
	"github.com/golang-jwt/jwt"
)

type AuthService interface {
	Login(request dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(params map[string]string) *errs.AppError
}

type DefaultAuthService struct {
	repo        domain.AuthRepository
	permissions domain.RolePermissions
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	login, err := s.repo.FindBy(req.Username, req.Password)

	if err != nil {
		return nil, err
	}

	token, err := login.GenerateToken()

	if err != nil {
		return nil, err
	}

	return &dto.LoginResponse{
		Token: *token,
	}, nil
}

func (s DefaultAuthService) Verify(params map[string]string) *errs.AppError {
	if jwtToken, err := jwtTokenFromString(params["token"]); err != nil {
		logger.Error("Something went wrong: " + err.Error())

		return errs.NewInternalServerError("Token is not valid")
	} else {
		if jwtToken.Valid {
			claims := jwtToken.Claims.(*domain.Claims)

			if claims.IsUserRole() && !claims.IsRequestVerifiedWithTokenClaims(params) {
				return errs.NewUnauthorizedError("Request is not verified with the token claims")
			}

			isAuthorized := s.permissions.IsAuthorizedFor(claims.Role, params["routeName"])
			if !isAuthorized {
				return errs.NewUnauthorizedError(fmt.Sprintf("%s role is not authorized", claims.Role))
			}

			return nil
		} else {
			return errs.NewUnauthorizedError("Token is not valid")
		}
	}
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})

	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())

		return nil, err
	}

	return token, nil
}

func CreateAuthService(r domain.AuthRepositoryDb, perm domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{
		repo:        r,
		permissions: perm,
	}
}

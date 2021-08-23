package application

import (
	"encoding/json"
	"encoding/xml"
	"github.com/aerostatka/banking-auth/domain"
	"github.com/aerostatka/banking-auth/dto"
	"github.com/aerostatka/banking-auth/service"
	"net/http"
)

type AuthHandlers struct {
	service service.AuthService
}

func (ah *AuthHandlers) Login(rw http.ResponseWriter, r *http.Request) {
	var request dto.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&request)

	if err != nil {
		writeResponse(rw, http.StatusBadRequest, "application/json", err.Error())
	} else {
		token, appErr := ah.service.Login(request)

		if appErr != nil {
			writeResponse(rw, appErr.Code, "application/json", appErr.Message)
		} else {
			writeResponse(rw, http.StatusOK, "application/json", *token)
		}
	}
}

func (ah *AuthHandlers) Verify(rw http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)

	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		isAuthorized, appErr := ah.service.Verify(urlParams)

		if appErr != nil {
			writeResponse(rw, appErr.Code, "application/json", appErr.Message)
		} else {
			if isAuthorized {
				writeResponse(rw, http.StatusOK, "application/json", authorizedRequest())
			} else {
				writeResponse(rw, http.StatusUnauthorized, "application/json", unauthorizedRequest())
			}
		}
	} else {
		writeResponse(rw, http.StatusForbidden, "application/json", "Missing token")
	}
}

func authorizedRequest() domain.AuthorizationRequest {
	return domain.AuthorizationRequest{
		IsAuthorized: true,
	}
}

func unauthorizedRequest() domain.AuthorizationRequest {
	return domain.AuthorizationRequest{
		IsAuthorized: false,
	}
}

func writeResponse(rw http.ResponseWriter, code int, contentType string, data interface{}) {
	rw.Header().Add("Content-Type", contentType)
	rw.WriteHeader(code)
	var err error
	switch contentType {
	case "application/xml":
		err = xml.NewEncoder(rw).Encode(data)
	case "application/json":
		err = json.NewEncoder(rw).Encode(data)
	default:
	}

	if err != nil {
		panic(err)
	}
}

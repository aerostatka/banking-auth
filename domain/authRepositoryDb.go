package domain

import (
	"database/sql"
	"github.com/aerostatka/banking-lib/errs"
	"github.com/aerostatka/banking-lib/logger"
	"github.com/jmoiron/sqlx"
)

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func NewAuthRepositoryDb(db *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{
		client: db,
	}
}

func (r AuthRepositoryDb) FindBy(user string, pass string) (*Login, *errs.AppError) {
	var login Login
	sqlVerify := `SELECT u.username, u.customer_id, u.role, GROUP_CONCAT(a.account_id) AS account_numbers
FROM users u
LEFT JOIN accounts a ON a.customer_id = u.customer_id
WHERE username = ? AND password = ?
GROUP BY u.customer_id`

	err := r.client.Get(&login, sqlVerify, user, pass)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewUnauthorizedError("User is unauthorized")
		} else {
			logger.Error("Error while verifying user in database: " + err.Error())
			return nil, errs.NewInternalServerError("Unexpected database error")
		}
	}

	return &login, nil
}

func (r AuthRepositoryDb) GenerateAndSaveRefreshToken(authToken *AuthToken) (string, *errs.AppError) {
	refreshToken, appErr := authToken.newRefreshToken()

	if appErr != nil {
		return "", appErr
	}

	sqlInsert := "INSERT INTO `refresh_token_store`(refresh_token) VALUES(?)"
	_, err := r.client.Exec(sqlInsert, refreshToken)

	if err != nil {
		logger.Error("Error while inserting refresh token: " + err.Error())

		return "", errs.NewInternalServerError("Unexpected database error")
	}

	return refreshToken, nil
}

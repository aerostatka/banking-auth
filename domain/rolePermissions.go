package domain

import (
	"github.com/aerostatka/banking-lib/logger"
	"strings"
)

type RolePermissions struct {
	rolePermissions map[string][]string
}

func (perm *RolePermissions) IsAuthorizedFor(role string, route string) bool {
	perms := perm.rolePermissions[role]

	for _, r := range perms {
		logger.Error(r)
		if r == strings.TrimSpace(route) {
			return true
		}
	}

	return false
}

func GetRolePermissions() RolePermissions {
	return RolePermissions{rolePermissions: map[string][]string{
		"admin": {"GetAllCustomers", "GetCustomer", "NewAccount", "NewTransaction"},
		"user":  {"GetCustomer", "NewTransaction"},
	}}
}

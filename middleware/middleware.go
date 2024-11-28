package middleware

import (
	"authentication.go/utils"
	"net/http"
	"slices"
)

func CheckRoleMiddleware(next http.Handler, roles ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Токен отсутствует", http.StatusUnauthorized)
			return
		}

		claims, err := utils.TokenParse(tokenString)
		if err != nil {
			utils.ResponseError(w, http.StatusUnauthorized, "Неправильный токен")
			return
		}

		userRole, ok := claims["role"].(string)
		if !ok || !slices.Contains(roles, userRole) {
			utils.ResponseError(w, http.StatusForbidden, "Нет доступа!")
			return
		}

		next.ServeHTTP(w, r)
	})
}

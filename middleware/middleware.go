package middleware

import (
	"authentication.go/utils"
	"net/http"
)

func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Токен отсутствует", http.StatusUnauthorized)
			return
		}

		// Проверяем токен
		claims, err := utils.TokenParse(tokenString)
		if err != nil {
			http.Error(w, "Неправильный токен", http.StatusUnauthorized)
			return
		}

		role, ok := claims["role"].(string)
		if !ok || role != "admin" {
			http.Error(w, "Нет доступа!", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

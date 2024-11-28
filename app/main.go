package main

import (
	"authentication.go/db"
	"authentication.go/handler"
	"authentication.go/middleware"
	"authentication.go/models/roles"
	"database/sql"
	_ "github.com/lib/pq"
	"log"
	"net/http"
)

func main() {
	db.ConnectDB()

	http.HandleFunc("/sign-up", handler.SignUpHandler)
	http.HandleFunc("/change", handler.ChangePassword)
	http.HandleFunc("/sign-in", handler.SignInHandler)
	http.HandleFunc("/get-info", handler.GettokenInfo)
	http.HandleFunc("/refresh", handler.RefreshToken)
	http.HandleFunc("/my-info", handler.MyInfo)
	http.Handle("/users", middleware.CheckRoleMiddleware(http.HandlerFunc(handler.GetUsers), roles.ADMIN, roles.SUPERVISOR))
	http.Handle("/user-id", middleware.CheckRoleMiddleware(http.HandlerFunc(handler.GetUserID), roles.ADMIN, roles.SUPERVISOR))
	http.Handle("/dell-users", middleware.CheckRoleMiddleware(http.HandlerFunc(handler.DeleteUsers), roles.SUPERVISOR))
	http.Handle("/change-role", middleware.CheckRoleMiddleware(http.HandlerFunc(handler.ChangeRole), roles.SUPERVISOR))

	err := http.ListenAndServe("localhost:8080", nil)
	if err != nil {
		log.Println("Error listening:", err)
		return
	}
	defer func(DB *sql.DB) {
		err := DB.Close()
		if err != nil {
			log.Println("Ошибка при закрытии базы данных:", err)
		}
	}(db.DB)
}

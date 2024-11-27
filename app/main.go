package main

import (
	"converter.go/db"
	"converter.go/handler"
	"converter.go/middleware"
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
	http.Handle("/users", middleware.AdminMiddleware(http.HandlerFunc(handler.GetUsers)))
	http.Handle("/user-id", middleware.AdminMiddleware(http.HandlerFunc(handler.GetUserID)))

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

package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type Config struct {
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
	SSLMode  string `json:"sslmode"`
}

var DB *sql.DB

func ConnectDB() {
	file, err := os.Open("../config.json")
	if err != nil {
		log.Fatalf("Ошибка открытия файла конфигурации: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Println("Ошибка при закрытии файла конфигурации:", err)
		}
	}(file)
	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		log.Fatalf("Ошибка декодирования JSON: %v", err)
	}
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=%s", config.User, config.Password, config.DBName, config.SSLMode)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	DB = db

	log.Println("Connected to database")

	return
}

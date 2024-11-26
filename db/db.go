package db

import (
	"database/sql"
	"log"
)

var DB *sql.DB

func ConnectDB() {

	db, err := sql.Open("postgres", "user=arno password=909209866sh dbname=arno_db sslmode=disable")
	if err != nil {
		panic(err)
	}

	DB = db

	log.Println("Connected to database")

	return
}

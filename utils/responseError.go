package utils

import (
	"encoding/json"
	"log"
	"net/http"
)

type Responserr struct {
	Message any `json:"message"`
}

func ResponseError(w http.ResponseWriter, statusCode int, message any) {
	w.Header().Set("Content-Type", "application/json")

	responserr := Responserr{
		Message: message,
	}

	bytes, _ := json.Marshal(responserr)

	w.WriteHeader(statusCode)

	_, err := w.Write(bytes)
	if err != nil {
		log.Println("Ошибка при чтении:", err)
		return
	}
}

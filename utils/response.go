package utils

import (
	"encoding/json"
	"log"
	"net/http"
)

type Respons struct {
	Message any `json:"message"`
}

func Response(w http.ResponseWriter, statusCode int, message any) {
	w.Header().Set("Content-Type", "application/json")
	response := Respons{
		Message: message,
	}
	w.WriteHeader(statusCode)

	marshal, err := json.Marshal(response)
	if err != nil {
		return
	}
	_, err = w.Write(marshal)
	if err != nil {
		log.Println("Ошибка при чтении:", err)
		return
	}
}

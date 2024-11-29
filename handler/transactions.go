package handler

import (
	"authentication.go/db"
	"authentication.go/models"
	"authentication.go/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func GetTransaction(w http.ResponseWriter, r *http.Request) {
	bytesBody, err := io.ReadAll(r.Body)
	if err != nil {
		utils.ResponseError(w, http.StatusBadRequest, "Плохое тело запроса")
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println("Ошибка при закрытии тела запроса:", err)
		}
	}(r.Body)

	var trans models.TransactionsEntities
	err = json.Unmarshal(bytesBody, &trans)
	if err != nil {
		log.Println(err)
		utils.ResponseError(w, http.StatusBadRequest, "Ошибка при чтении тела запроса")
		return
	}

	if trans.From == "" || trans.To == "" {
		utils.ResponseError(w, http.StatusBadRequest, "Должны быть указаны даты `from` и `to`")
		return
	}

	query := "SELECT amount, sender, receiver, created_at FROM transactions WHERE created_at BETWEEN $1 AND $2"
	args := []interface{}{trans.From, trans.To}

	paramIndex := 3

	if trans.Sender != nil && *trans.Sender != "" {
		query += fmt.Sprintf(" AND sender = $%d", paramIndex)
		args = append(args, *trans.Sender)
		paramIndex++
	}

	if trans.Receiver != nil && *trans.Receiver != "" {
		query += fmt.Sprintf(" AND receiver = $%d", paramIndex)
		args = append(args, *trans.Receiver)
		paramIndex++
	}

	if trans.Amount != nil {
		query += fmt.Sprintf(" AND amount = $%d", paramIndex)
		args = append(args, *trans.Amount)
		paramIndex++
	}

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		log.Println("Ошибка запроса в базу данных", err)
		utils.ResponseError(w, http.StatusInternalServerError, "Ошибка при получении данных")
		return
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			log.Println("Ошибка при закрытии базы данных:", err)
		}
	}(rows)

	var transactions []models.TransactionsEntities
	for rows.Next() {
		var transaction models.TransactionsEntities
		err := rows.Scan(&transaction.Amount, &transaction.Sender, &transaction.Receiver, &transaction.From)
		if err != nil {
			log.Println("Ошибка при сканировании строки:", err)
			utils.ResponseError(w, http.StatusInternalServerError, "Ошибка при обработке данных")
			return
		}
		transactions = append(transactions, transaction)
	}

	if len(transactions) == 0 {
		utils.ResponseError(w, http.StatusNotFound, "Транзакции не найдены")
		return
	}

	utils.Response(w, http.StatusOK, transactions)
}

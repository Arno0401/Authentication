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
	"time"
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

	type getTransactionRequest struct {
		From     string   `json:"from"`
		To       string   `json:"to"`
		Limit    *int     `json:"limit"`
		Page     *int     `json:"page"`
		Sender   *string  `json:"sender"`
		Receiver *string  `json:"receiver"`
		Amount   *float64 `json:"amount"`
		Status   *int     `json:"status"`
	}

	var input getTransactionRequest
	err = json.Unmarshal(bytesBody, &input)
	if err != nil {
		log.Println(err)
		utils.ResponseError(w, http.StatusBadRequest, "Ошибка при чтении тела запроса")
		return
	}

	log.Println(string(bytesBody))
	log.Printf("%+v", input)

	dateFrom, err := time.Parse("2006-01-02 15:04:05", input.From)
	if err != nil {
		utils.ResponseError(w, http.StatusBadRequest, "Неправильная дата `from`")
		return
	}

	dateTo, err := time.Parse("2006-01-02 15:04:05", input.To)
	if err != nil {
		utils.ResponseError(w, http.StatusBadRequest, "Неправильная дата `to`")
		return
	}

	if !dateTo.After(dateFrom) {
		utils.ResponseError(w, http.StatusBadRequest, "Дата `to` должна быть больше даты `from`")
		return
	}
	limitTrans := 10
	if input.Limit != nil {
		limitTrans = *input.Limit
	}
	pageTrans := 1
	if input.Page != nil {
		pageTrans = *input.Page
	}
	query := "SELECT amount, sender, receiver, created_at, status FROM transactions WHERE created_at BETWEEN $1 AND $2"
	args := []interface{}{dateFrom, dateTo}

	paramIndex := 3

	if input.Sender != nil && *input.Sender != "" {
		query += fmt.Sprintf(" AND sender = $%d", paramIndex)
		args = append(args, *input.Sender)
		paramIndex++
	}

	if input.Receiver != nil && *input.Receiver != "" {
		query += fmt.Sprintf(" AND receiver = $%d", paramIndex)
		args = append(args, *input.Receiver)
		paramIndex++
	}

	if input.Amount != nil {
		query += fmt.Sprintf(" AND amount = $%d", paramIndex)
		args = append(args, *input.Amount)
		paramIndex++
	}

	if input.Status != nil {
		query += fmt.Sprintf(" AND status = $%d", paramIndex)
		args = append(args, *input.Status)
		paramIndex++
	}

	query += ` ORDER BY created_at DESC`

	if limitTrans != 0 {
		if limitTrans > 500 {
			limitTrans = 500
		}
		query += fmt.Sprintf(" LIMIT $%d", paramIndex)
		args = append(args, limitTrans)
		paramIndex++
	}

	if pageTrans != 0 {
		query += fmt.Sprintf(" OFFSET $%d", paramIndex)
		args = append(args, (pageTrans-1)*limitTrans)
		paramIndex++
	}

	if pageTrans <= 0 {
		utils.ResponseError(w, http.StatusBadRequest, "Страница не может быть отрицательной")
		return
	}

	if limitTrans <= 0 {
		utils.ResponseError(w, http.StatusBadRequest, "Лимит не может быть отрицательным")
		return
	}

	log.Println(query)

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
		err := rows.Scan(&transaction.Amount, &transaction.Sender, &transaction.Receiver, &transaction.CreatedAt, &transaction.Status)
		if err != nil {
			log.Println("Ошибка при сканировании строки:", err)
			utils.ResponseError(w, http.StatusInternalServerError, "Ошибка при обработке данных")
			return
		}
		if transaction.Status != nil {
			transaction.StatusName = models.GetStatusDescription(*transaction.Status)
		}
		transactions = append(transactions, transaction)
	}

	if len(transactions) == 0 {
		utils.ResponseError(w, http.StatusNotFound, "Транзакции не найдены")
		return
	}

	utils.Response(w, http.StatusOK, transactions)
}

package models

import "time"

type TransactionsEntities struct {
	CreatedAt  time.Time `json:"created_at"`
	Sender     *string   `json:"sender"`
	Receiver   *string   `json:"receiver"`
	Amount     *float64  `json:"amount"`
	Status     *int      `json:"status"`
	StatusName string    `json:"status_name"`
}

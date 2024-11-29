package models

type TransactionsEntities struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Sender   *string  `json:"sender"`
	Receiver *string  `json:"receiver"`
	Amount   *float64 `json:"amount"`
}

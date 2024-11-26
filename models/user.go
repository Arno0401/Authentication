package models

type User struct {
	ID       int    `json:"id"`
	FullName string `json:"full_name"`
	Login    string `json:"login"`
	Password string `json:"-"`
	Role     string `json:"role"`
}

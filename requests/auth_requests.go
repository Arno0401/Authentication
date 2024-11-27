package requests

type SignUpRequest struct {
	FullName string `json:"full_name"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

type ChangePasswordRequest struct {
	Login       string `json:"login"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type SignInRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

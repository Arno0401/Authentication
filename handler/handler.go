package handler

import (
	converter "converter.go"
	"converter.go/db"
	"converter.go/models"
	"converter.go/utils"
	"database/sql"
	"encoding/json"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"slices"
	"time"
	"unicode"
)

func isUserExists(db *sql.DB, login string) (bool, error) {

	query := "SELECT COUNT(*) FROM users WHERE login = $1"

	var count int

	err := db.QueryRow(query, login).Scan(&count)
	if err != nil {
		log.Println("Ошибка запроса в базу данных", err)
		return false, err
	}
	log.Println(count)
	return count > 0, nil
}
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func insertUser(db *sql.DB, user converter.SignUpRequest) error {
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		log.Println("Ошибка при хешировании пароля:", err)
		return err
	}
	query := "INSERT INTO users (full_name, login, password, role) VALUES ($1, $2, $3, 'user')"

	_, err = db.Exec(query, user.FullName, user.Login, hashedPassword)

	return err
}

func SignUpHandler(w http.ResponseWriter, r *http.Request) {
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

	var singUp converter.SignUpRequest
	err = json.Unmarshal(bytesBody, &singUp)

	if err != nil {
		utils.ResponseError(w, http.StatusBadRequest, "Ошибка при чтении тела запроса")
		return
	}

	if !validateLogin(singUp.Login) {
		utils.ResponseError(w, http.StatusUnauthorized, "Логин должен быть больше 5 символов")
		return
	}

	if !validatePassword(singUp.Password) {
		utils.ResponseError(w, http.StatusUnauthorized, `Пароль должен быть больше 8 символов,
		содержать хотя бы одну цифру и один специальный символ`)
		return
	}

	exists, err := isUserExists(db.DB, singUp.Login)
	if err != nil {
		utils.ResponseError(w, http.StatusInternalServerError, "Произошла ошибка при проверке наличия пользователя")
		return
	}

	if exists {
		utils.ResponseError(w, http.StatusUnauthorized, "Пользователь с таким логином уже существует")
		return
	}

	err = insertUser(db.DB, singUp)
	if err != nil {
		log.Println(err)

		utils.ResponseError(w, http.StatusInternalServerError, "Произошла ошибка при создании пользователя")
		return
	}
	utils.Response(w, http.StatusOK, "Пользователь успешно зарегистрирован")
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {

	bytesBody, err := io.ReadAll(r.Body)
	if err != nil {
		utils.Response(w, http.StatusBadRequest, "Плохое тело запроса")
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println("Ошибка при закрытии тела запроса:", err)
		}
	}(r.Body)

	var changePass converter.ChangePasswordRequest
	err = json.Unmarshal(bytesBody, &changePass)

	exists, err := isUserExists(db.DB, changePass.Login)
	if err != nil {
		utils.ResponseError(w, http.StatusInternalServerError, "Произошла ошибка при проверке наличия пользователя")
		return
	}
	if exists {

		query := "SELECT password FROM users WHERE login = $1"

		var password string

		err := db.DB.QueryRow(query, changePass.Login).Scan(&password)
		if err != nil {
			log.Println("Ошибка запроса в базу данных", err)
		}
		err = bcrypt.CompareHashAndPassword([]byte(password), []byte(changePass.OldPassword))
		if err != nil {
			utils.Response(w, http.StatusUnauthorized, "Неправильный пароль")
			return
		}

		hashedPassword, err := hashPassword(changePass.NewPassword)
		if err != nil {
			log.Println("Ошибка при хешировании пароля:", err)
			return
		}
		query1 := `UPDATE users
			SET password = $2
			WHERE login = $1`

		_, err = db.DB.Exec(query1, changePass.Login, hashedPassword)
		if err != nil {
			log.Println("Ошибка при обновлении пароля:", err)
			return
		}
	}
	utils.Response(w, http.StatusOK, "Пароль успешно изменен")
}

func SignInHandler(w http.ResponseWriter, r *http.Request) {
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

	var signIn converter.SignInRequest
	err = json.Unmarshal(bytesBody, &signIn)

	exists, err := isUserExists(db.DB, signIn.Login)
	if err != nil {
		utils.ResponseError(w, http.StatusInternalServerError, "Произошла ошибка при проверке наличия пользователя")
		return
	}

	log.Println(exists)
	if exists {
		var user models.User

		query := "SELECT id, role, password FROM users WHERE login = $1;"

		err := db.DB.QueryRow(query, signIn.Login).Scan(&user.ID, &user.Role, &user.Password)
		if err != nil {
			log.Println("Ошибка запроса в базу данных", err)
		}
		log.Println(user.Password)
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(signIn.Password))
		if err != nil {
			utils.ResponseError(w, http.StatusUnauthorized, map[string]string{"error": "Неправильный пароль"})
			return
		}

		token, err := CreateToken(user)
		if err != nil {
			utils.ResponseError(w, http.StatusInternalServerError, "Произошла ошибка при создании refresh token")
			return
		}
		utils.Response(w, http.StatusOK, token)
	} else {
		utils.ResponseError(w, http.StatusUnauthorized, "Пользователь не найден")
	}
}

func GettokenInfo(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")

	mapClaims, err := utils.TokenParse(tokenString)
	if err != nil {
		utils.ResponseError(w, http.StatusUnauthorized, "Неправильный токен")
		return
	}
	err = mapClaims.Valid()
	if err != nil {
		utils.ResponseError(w, http.StatusUnauthorized, "Неправильный токен")
	}

	if mapClaims["type"] != "access" {
		utils.ResponseError(w, http.StatusUnauthorized, "Неправильный токен")
		return
	}

	utils.Response(w, http.StatusOK, mapClaims)
}

func MyInfo(w http.ResponseWriter, r *http.Request) {
	accessToken := r.Header.Get("Authorization")

	mapClaims, err := utils.TokenParse(accessToken)
	if err != nil {
		utils.ResponseError(w, http.StatusUnauthorized, "Неправильный токен")
		return
	}

	userID, ok := mapClaims["id"].(float64)
	if !ok {
		utils.ResponseError(w, http.StatusUnauthorized, "Неправильный формат ID пользователя")
		return
	}

	var user models.User

	query := "SELECT id, full_name, login, role FROM users WHERE id = $1;"

	err = db.DB.QueryRow(query, int(userID)).Scan(&user.ID, &user.FullName, &user.Login, &user.Role)
	if err != nil {
		utils.ResponseError(w, http.StatusInternalServerError, "Ошибка запроса в базу данных")
		return
	}

	utils.Response(w, http.StatusOK, user)
}

func GetUsers(w http.ResponseWriter, r *http.Request) {

	id := r.URL.Query().Get("id")

	if id != "" {
		var user models.User
		query := "SELECT id, full_name, login, role FROM users WHERE id = $1"
		err := db.DB.QueryRow(query, id).Scan(&user.ID, &user.FullName, &user.Login, &user.Role)
		if err != nil {
			if err == sql.ErrNoRows {
				utils.ResponseError(w, http.StatusNotFound, "Пользователь не найден")
			} else {
				utils.ResponseError(w, http.StatusInternalServerError, "Ошибка при получении пользователя")
			}
			return
		}
		utils.Response(w, http.StatusOK, user)
		return
	}

	users, err := db.DB.Query("SELECT id, full_name, login, role FROM users order by id desc")
	if err != nil {
		utils.ResponseError(w, http.StatusInternalServerError, "Произошла ошибка при получении пользователей")
		return
	}
	defer func(users *sql.Rows) {
		err := users.Close()
		if err != nil {
			log.Println("Ошибка при закрытии базы данных:", err)
		}
	}(users)

	var usersInfo []models.User

	for users.Next() {
		var user models.User
		err := users.Scan(&user.ID, &user.FullName, &user.Login, &user.Role)
		if err != nil {
			utils.ResponseError(w, http.StatusInternalServerError, "Произошла ошибка при получении пользователей")
			return
		}
		usersInfo = append(usersInfo, user)
	}

	utils.Response(w, http.StatusOK, usersInfo)

}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	type refreshTokenRequest struct {
		RefreshToken string `json:"refresh_token"`
	}

	bytes, err := io.ReadAll(r.Body)
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

	var input refreshTokenRequest
	err = json.Unmarshal(bytes, &input)
	if err != nil {
		utils.ResponseError(w, http.StatusBadRequest, "Плохое тело запроса")
		return
	}

	mapClaims, err := utils.TokenParse(input.RefreshToken)
	if err != nil {
		utils.ResponseError(w, http.StatusUnauthorized, "Неправильный токен")
		return
	}

	if mapClaims["type"] != "refresh" {
		utils.ResponseError(w, http.StatusUnauthorized, "Неправильный токен")
		return
	}

	userID, ok := mapClaims["id"].(float64)
	if !ok {
		utils.ResponseError(w, http.StatusUnauthorized, "Ошибка в ID пользователя")
		return
	}

	role, ok := mapClaims["role"].(string)
	if !ok {
		utils.ResponseError(w, http.StatusUnauthorized, "Ошибка в роли пользователя")
		return
	}

	user := models.User{
		ID:   int(userID),
		Role: role,
	}

	newTokens, err := CreateToken(user)
	if err != nil {
		utils.ResponseError(w, http.StatusInternalServerError, "Произошла ошибка при создании refresh token")
		return
	}

	utils.Response(w, http.StatusOK, newTokens)
}

func CreateToken(user models.User) (models.Token, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   user.ID,
		"role": user.Role,
		"type": "access",
		"exp":  time.Now().Add(time.Minute * 10).Unix(),
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   user.ID,
		"role": user.Role,
		"type": "refresh",
		"exp":  time.Now().Add(time.Hour * 120).Unix(),
	})

	signedAccessToken, err := accessToken.SignedString([]byte("Arno"))
	if err != nil {
		return models.Token{}, err
	}

	signedRefreshToken, err := refreshToken.SignedString([]byte("Arno"))
	if err != nil {
		return models.Token{}, err
	}

	tokens := models.Token{
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
	}

	return tokens, nil
}

func validateLogin(login string) bool {
	return len(login) >= 5
}

func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	HasNumber := false
	HasSymbol := false
	Haslett := false

	for _, char := range password {
		if unicode.IsDigit(char) {
			HasNumber = true
		} else if unicode.IsLetter(char) {
			Haslett = true
		} else if isSymbol(char) {
			HasSymbol = true
		}
	}

	return Haslett && HasSymbol && HasNumber
}

func isSymbol(char rune) bool {
	symbols := []rune{'!', '@', '#', '$', '%', '^', '&', '*'}
	return slices.Contains(symbols, char)
}

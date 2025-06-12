package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// ✅ Define User struct at the top
type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

// ✅ Dummy user list
var users = []User{
	{ID: 1, Email: "alice@example.com"},
	{ID: 2, Email: "bob@example.com"},
}

// 🔓 BOLA vulnerability example
func GetUserByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idParam := vars["id"]

	id, err := strconv.Atoi(idParam)
	if err != nil {
		http.Error(w, "Invalid IDDD", http.StatusBadRequest)
		return
	}

	for _, user := range users {
		if user.ID == id {
			json.NewEncoder(w).Encode(user)
			return
		}
	}

	http.Error(w, "User not found", http.StatusNotFound)
}

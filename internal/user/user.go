package user

type Role struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	AllowedModules []string `json:"allowedModules"`
	CreatedAt      int64    `json:"createdAt"`
}

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	RoleID       string `json:"roleId"`
	DisplayName  string `json:"displayName,omitempty"`
	CreatedAt    int64  `json:"createdAt"`
	UpdatedAt    int64  `json:"updatedAt"`
	Role         *Role  `json:"role,omitempty"`
}

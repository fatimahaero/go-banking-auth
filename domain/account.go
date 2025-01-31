package domain

type Account struct {
	ID          string  `json:"acc_id" db:"id"`
	Customer_ID string  `json:"cust_id" db:"customer_id" validate:"required,uuid"`
	Username    string  `json:"acc_username,omitempty" db:"username" validate:"required,min=3,max=100,omitempty"`
	Password    string  `json:"acc_password,omitempty" db:"password" validate:"required,min=8,max=100,omitempty"`
	Balance     float64 `json:"acc_balance" db:"balance" validate:"gte=0,min=0"`
	Currency    string  `json:"acc_currency" db:"currency" validate:"required,len=3"`
	Status      bool    `json:"acc_status" db:"status" validate:"boolean"`
}

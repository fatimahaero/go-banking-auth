package main

import (
	"github.com/fatimahaero/go-banking-auth/routes"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	routes.StartServer()
}

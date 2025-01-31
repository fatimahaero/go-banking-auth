package utils

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

func CustomValidationError(err error) string {
	var errors []string

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, fieldErr := range validationErrors {
			switch fieldErr.Tag() {
			case "required":
				errors = append(errors, fmt.Sprintf("%s is required", fieldErr.Field()))
			case "gte":
				errors = append(errors, fmt.Sprintf("%s must be greater than or equal to %s", fieldErr.Field(), fieldErr.Param()))
			case "lte":
				errors = append(errors, fmt.Sprintf("%s must be less than or equal to %s", fieldErr.Field(), fieldErr.Param()))
			case "min":
				errors = append(errors, fmt.Sprintf("%s must be at least %s characters long", fieldErr.Field(), fieldErr.Param()))
			case "max":
				errors = append(errors, fmt.Sprintf("%s must be at most %s characters long", fieldErr.Field(), fieldErr.Param()))
			default:
				errors = append(errors, fmt.Sprintf("%s is invalid", fieldErr.Field()))
			}
		}
		return strings.Join(errors, ", ")
	}

	return err.Error()
}

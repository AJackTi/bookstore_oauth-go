package errors

import (
	"fmt"
	"net/http"
)

type RestErr struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// standard error is made based on the error code or a custom error is made based on the message provided.
func New(code int, message ...string) *RestErr {
	var restErr *RestErr

	if len(message) == 0 {
		fmt.Printf("Error code:%d was thrown by applicaton...", code)
		switch code {
		case 400:
			restErr = &RestErr{
				Status: http.StatusBadRequest,
				Title:  "BAD REQUEST",
				Detail: "The server cannot or will not process the request due to something that is perceived to be a client error",
			}
		case 401:
			fmt.Println("Unauthorized")
			restErr = &RestErr{
				Status: http.StatusUnauthorized,
				Title:  "UNAUTHORIZED",
				Detail: "The request has not been applied because it lacks valid authentication credentials for the target resource",
			}
		case 404:
			restErr = &RestErr{
				Status: http.StatusNotFound,
				Title:  "NOT FOUND",
				Detail: "The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.",
			}
		case 500:
			restErr = &RestErr{
				Status: http.StatusInternalServerError,
				Title:  "INTERNAL SERVER ERROR",
				Detail: "The server encountered an unexpected condition that prevented it from fulfilling the request.",
			}
		default:
			restErr = &RestErr{
				Status: http.StatusNotAcceptable,
				Title:  "SERVICE UNAVAILABLE",
				Detail: "The server is currently unable to handle the request due to a temporary overload or scheduled maintenance, which will likely be alleviated after some delay",
			}
		}
	} else {
		fmt.Println("Custom Bad request error")
		restErr = &RestErr{
			Status: code,
			Title:  "Something went wrong",
			Detail: message[0],
		}
	}

	return restErr
}

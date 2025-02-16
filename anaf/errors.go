package anaf

import "fmt"

type AnafResponseError struct {
	Msg  string
	Code int
}

func (e *AnafResponseError) Error() string {
	if e.Code == 0 {
		return e.Msg
	}
	return fmt.Sprintf("%s (status %d)", e.Msg, e.Code)
}

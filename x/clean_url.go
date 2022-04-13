package x

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
)

func CleanPath(stripPaths []string) func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		r.URL.Path = httprouter.CleanPath(r.URL.Path)
		for _, prefix := range stripPaths {
			fmt.Println(prefix)
			if strings.HasPrefix(r.URL.Path, prefix) {
				r.URL.Path = strings.Replace(r.URL.Path, prefix, "", 1)
				fmt.Println(r.URL.Path)
				break
			}
		}
		next(rw, r)
	}
}

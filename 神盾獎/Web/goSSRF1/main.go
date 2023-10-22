package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/exp/utf8string"
)

func main() {

	router := gin.Default()
	router.GET("/api", func(c *gin.Context) {
		urlQuery := c.Query("url")
		url, err := url.Parse("http://" + urlQuery)
		isASC := utf8string.NewString(url.Host).IsASCII()
		urlLower := strings.ToLower(url.Host + url.RequestURI())
		if !isASC || strings.Contains(urlLower, "localhost") || strings.Contains(urlLower, "127.0.0.1") || strings.Contains(urlLower, "0.0.0.0") {
			c.Writer.WriteHeader(http.StatusBadRequest)
			c.Writer.Write([]byte(`
			█░█ █▀█ █▀█   █▄▄ ▄▀█ █▀▄   █▀█ █▀▀ █▀█ █░█ █▀▀ █▀ ▀█▀
			▀▀█ █▄█ █▄█   █▄█ █▀█ █▄▀   █▀▄ ██▄ ▀▀█ █▄█ ██▄ ▄█ ░█░
			`))
			return
		}
		if err != nil {
			fmt.Println(err)
		}
		m, _ := regexp.Match(".*.com.tw", []byte(url.String()))
		if m {
			resp, err := http.Get("http://" + urlLower)
			if err != nil {
				fmt.Println(err)
			} else {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Println(err)
				}
				c.Writer.WriteHeader(http.StatusOK)
				c.Writer.Write([]byte(`
				▀█ █▀█ █▀█   █▀█ █▄▀
				█▄ █▄█ █▄█   █▄█ █░█
				`))
				c.Writer.Write(body)
			}
			defer resp.Body.Close()
		}
	})
	router.Run(":8081")
}

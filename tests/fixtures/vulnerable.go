package main

import (
	"crypto/tls"
	"crypto/md5"
	"fmt"
	"net/http"
	"os/exec"
)

func vulnerable() {
	userInput := getUserInput()

	// 1. go/no-sql-injection — string concat (Critical)
	query1 := "SELECT * FROM users WHERE id = " + userInput

	// 2. go/no-sql-injection — fmt.Sprintf (Critical)
	query2 := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userInput)

	// 3. go/no-command-injection (Critical)
	exec.Command(userInput)

	// 4. go/no-hardcoded-secret (High)
	apiKey := "sk-live-abcdef123456789"

	// 5. go/no-weak-crypto (Medium) — import already triggers, plus usage:
	md5.New()

	// 6. go/no-ssrf (High)
	http.Get(userInput)

	// 7. go/net-http-no-timeout (Medium)
	http.ListenAndServe(":8080", nil)

	// 8. go/insecure-tls-skip-verify (High)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	_ = query1
	_ = query2
	_ = apiKey
	_ = transport
}

func getUserInput() string {
	return "malicious"
}

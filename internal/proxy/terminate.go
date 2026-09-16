package proxy

import "net/http"

const DefaultTerminateURL = "/"

var TerminationURLs = map[string]string{}

func ShouldTerminate(session any, r *http.Request) bool {
	_ = session
	_ = r
	return false
}

func DoTerminate(w http.ResponseWriter, session any, r *http.Request) {
	_ = w
	_ = session
	_ = r
}

func Terminate(w http.ResponseWriter, targetName string) {
	_ = w
	_ = targetName
}

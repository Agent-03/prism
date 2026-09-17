package main

import "net/http"

var terminationURLs = map[string]string{}

const defaultTerminateURL = "/"

func shouldTerminate(s *Session, r *http.Request) bool {
	_ = s
	_ = r
	return false
}

func doTerminate(w http.ResponseWriter, s *Session, r *http.Request) {
	_ = w
	_ = s
	_ = r
}

func isAssetPath(path string) bool {
	_ = path
	return false
}

package bripguard

import (
	"net/http"
	"strings"
	"time"
)

func (g *BripGuard) GuardOn(paths []string) func(http.Handler) http.Handler {
	pathsMp := map[string]bool{}
	for i := range paths {
		pathsMp[sanitizeUrl(paths[i])] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pth := sanitizeUrl(r.URL.Path)
			if strings.Contains(pth, g.cfg.BripPath+releasePath) {
				parts := strings.Split(pth, "/")
				ch, err := g.GetChallenge(parts[len(parts)-1])
				if err != nil {
					http.Error(w, "not releasing the challenge", 400)
					return
				}
				w.WriteHeader(200)
				w.Write([]byte(ch))
				return
			}

			if strings.Contains(pth, g.cfg.BripPath+verifyPath) {
				parts := strings.Split(pth, "/")
				tkn := parts[len(parts)-1]
				if v, err := g.VerifyToken(string(tkn), r); err == nil && v {
					g.setCookie(string(tkn), w)
					w.WriteHeader(200)
					w.Write([]byte("ok"))
					return
				}

				http.Error(w, "not verified the challeneg token", 400)
				return
			}

			if strings.Contains(pth, g.cfg.BripPath+tokenPath) {
				tkn, err := g.GenerateToken(r)
				if err != nil {
					http.Error(w, "|invalid token request|", 400)
					return
				}
				w.WriteHeader(200)
				w.Write([]byte(tkn))
				return
			}

			if !pathsMp[pth] && !pathsMp["/*"] {
				next.ServeHTTP(w, r)
				return
			}

			if _, v, err := g.VerifyFinalToken(r); err == nil && v {
				next.ServeHTTP(w, r)
				return
			}

			g.putSession(w, 10)
		})
	}
}

func (g *BripGuard) putSession(w http.ResponseWriter, delayInMs int) {
	if sessionId, err := g.CreateSession(delayInMs); err == nil {
		str := "{\"challenge\":\"" + g.cfg.BripPath + releasePath + sessionId + "\"}"
		w.WriteHeader(http.StatusLocked)
		w.Write([]byte(str))
		return
	}
	http.Error(w, "Seems the service is experiencing some issue, please try again later", http.StatusInternalServerError)
}

func sanitizeUrl(url string) string {
	if len(url) == 0 {
		return "/"
	}
	for len(url) > 0 && url[len(url)-1] == '/' {
		url = url[0 : len(url)-1]
	}
	if len(url) == 0 || url[0] != '/' {
		url = "/" + url
	}
	return url
}

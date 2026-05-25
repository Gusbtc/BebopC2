package version

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"c2/ui"
)

const (
	Current = "1.5.0"
	repo    = "https://api.github.com/repos/Gusbtc/BebopC2/releases/latest"
)

type ghRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

func CheckForUpdates() {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(repo)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return
	}

	remote := strings.TrimPrefix(rel.TagName, "v")
	if remote != "" && isNewerVersion(remote, Current) {
		ui.Blank()
		ui.Action("update", fmt.Sprintf("new version available: %s (current: %s)", remote, Current))
		ui.Detail(rel.HTMLURL)
		ui.Blank()
	}
}

func isNewerVersion(remote, current string) bool {
	parse := func(v string) ([]int, bool) {
		parts := strings.Split(v, ".")
		out := make([]int, 0, len(parts))
		for _, part := range parts {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, false
			}
			out = append(out, n)
		}
		return out, true
	}

	rv, rok := parse(remote)
	cv, cok := parse(current)
	if !rok || !cok {
		return remote != current
	}

	maxLen := len(rv)
	if len(cv) > maxLen {
		maxLen = len(cv)
	}
	for i := 0; i < maxLen; i++ {
		r := 0
		c := 0
		if i < len(rv) {
			r = rv[i]
		}
		if i < len(cv) {
			c = cv[i]
		}
		if r > c {
			return true
		}
		if r < c {
			return false
		}
	}
	return false
}

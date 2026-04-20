package version

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"c2/ui"
)

const (
	Current = "1.1.0"
	repo    = "https://api.github.com/repos/Gusbtc/Bepop-Framework/releases/latest"
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
	if remote != "" && remote != Current {
		ui.Blank()
		ui.Action("update", fmt.Sprintf("new version available: %s (current: %s)", remote, Current))
		ui.Detail(rel.HTMLURL)
		ui.Blank()
	}
}

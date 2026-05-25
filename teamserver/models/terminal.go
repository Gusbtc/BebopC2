package models

type TerminalEntry struct {
	Text string `json:"text"`
	Cls  string `json:"cls"`
}

type FileBrowserNode struct {
	Entries []map[string]interface{} `json:"entries,omitempty"`
	Error   string                   `json:"error,omitempty"`
	Touched int64                    `json:"touched,omitempty"`
}

type FileBrowserCache struct {
	Tree     map[string]FileBrowserNode `json:"tree,omitempty"`
	Expanded []string                   `json:"expanded,omitempty"`
	Selected string                     `json:"selected,omitempty"`
	Root     string                     `json:"root,omitempty"`
	Sep      string                     `json:"sep,omitempty"`
	SavedAt  int64                      `json:"saved_at,omitempty"`
}

type TerminalState struct {
	OutputLog          []TerminalEntry   `json:"output_log"`
	CmdHistory         []string          `json:"cmd_history"`
	PollSince          int64             `json:"poll_since"`
	FileBrowser        *FileBrowserCache `json:"file_browser,omitempty"`
	SessionFileBrowser *FileBrowserCache `json:"session_file_browser,omitempty"`
}

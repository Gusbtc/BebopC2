package models

type TerminalEntry struct {
	Text string `json:"text"`
	Cls  string `json:"cls"`
}

type TerminalState struct {
	OutputLog  []TerminalEntry `json:"output_log"`
	CmdHistory []string        `json:"cmd_history"`
	PollSince  int64           `json:"poll_since"`
}

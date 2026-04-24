package ui

import (
	"fmt"
	"os"
	"strings"
)

var (
	amber  = "\033[38;5;214m"
	gray   = "\033[38;5;245m"
	green  = "\033[38;5;77m"
	red    = "\033[38;5;203m"
	bold   = "\033[1m"
	italic = "\033[3m"
	reset  = "\033[0m"
)

func init() {
	info, err := os.Stdout.Stat()
	if err != nil || (info.Mode()&os.ModeCharDevice) == 0 {
		amber, gray, green, red, bold, italic, reset = "", "", "", "", "", "", ""
	}
}

const labelWidth = 12
const lineWidth = 70

func pad(label string) string {
	if len(label) >= labelWidth {
		return label
	}
	return strings.Repeat(" ", labelWidth-len(label)) + label
}

func Banner() {
	fmt.Fprintf(os.Stdout, "\n%s", amber)
	fmt.Fprintln(os.Stdout, `    ____  ______ ____   ____   ____`)
	fmt.Fprintln(os.Stdout, `   / __ )/ ____// __ ) / __ \ / __ \`)
	fmt.Fprintln(os.Stdout, `  / __  / __/  / __  |/ / / // /_/ /`)
	fmt.Fprintln(os.Stdout, ` / /_/ / /___ / /_/ // /_/ // ____/`)
	fmt.Fprintln(os.Stdout, `/_____/_____//_____/ \____//_/`)
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "         %sC2 FRAMEWORK // EST. 2071%s\n", gray, reset)
	fmt.Fprintf(os.Stdout, "      %s\"3, 2, 1... Let's jam.\"%s\n\n", italic+gray, reset)
}

func Info(label, value string) {
	fmt.Fprintf(os.Stdout, "   %s::%s %s%s%s   %s\n", gray, reset, amber, pad(label), reset, value)
}

func Action(label, value string) {
	fmt.Fprintf(os.Stdout, "   %s>>%s %s%s%s   %s\n", amber, reset, amber, pad(label), reset, value)
}

func Success(label, value string) {
	content := fmt.Sprintf("   >> %s   %s", pad(label), value)
	padding := ""
	if len(content) < lineWidth-4 {
		padding = strings.Repeat(" ", lineWidth-4-len(content))
	}
	fmt.Fprintf(os.Stdout, "   %s>>%s %s%s%s   %s%s%s[ok]%s\n",
		amber, reset, amber, pad(label), reset, value, padding, green, reset)
}

func Error(label, value string) {
	fmt.Fprintf(os.Stdout, "   %s!!%s %s%s%s   %s%s%s\n",
		red, reset, red, pad(label), reset, red, value, reset)
}

func Detail(value string) {
	fmt.Fprintf(os.Stdout, "   %s%s%s%s\n",
		strings.Repeat(" ", labelWidth+5), gray, value, reset)
}

func Quote(phrase string) {
	fmt.Fprintf(os.Stdout, "   %s%s\"%s\"%s\n",
		strings.Repeat(" ", labelWidth+5), italic+gray, phrase, reset)
}

func Prompt(label string) {
	fmt.Fprintf(os.Stdout, "\n   %s>>%s %s%s%s   ", amber, reset, amber, pad(label), reset)
}

func MenuHeader(value string) {
	fmt.Fprintf(os.Stdout, "\n   %s::%s %s\n", gray, reset, value)
}

func MenuItem(key, desc string) {
	fmt.Fprintf(os.Stdout, "      %s%s[%s]%s %s\n", amber, bold, key, reset, desc)
}

func Goodbye() {
	fmt.Fprintf(os.Stdout, "\n   %s\"See you, space cowboy...\"%s\n\n", amber, reset)
}

func Errorf(label, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "   %s!!%s %s%s%s   %s%s%s\n",
		red, reset, red, pad(label), reset, red, msg, reset)
}

func Blank() {
	fmt.Fprintln(os.Stdout)
}

func InputPrompt(label string) {
	fmt.Fprintf(os.Stdout, "      %s%s%s %s▸%s ", gray, strings.ToUpper(label), reset, amber, reset)
}

func Divider() {
	fmt.Fprintf(os.Stdout, "   %s%s%s\n", gray, strings.Repeat("─", 42), reset)
}

func CommandPrompt() {
	fmt.Fprintf(os.Stdout, "\n   %sBEBOP%s %s▸%s ", amber, reset, amber, reset)
}

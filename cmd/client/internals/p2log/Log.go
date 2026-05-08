package p2log

import (
	"fmt"
	"os"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
)

//Debug : details
//Info : normal events
//Warn : something go wrong
//Error : need attention

var file *os.File

func createLog(prototype string, color int, msg string, args ...any) {
	timestamp := time.Now().Format("02-01-2006 15:04:05")
	argsMsg := fmt.Sprint(args...)
	Logmsg := fmt.Sprintf("[%s] [%s] %s %v", timestamp, prototype, msg, argsMsg)

	var color2 string
	switch color {
	case 1:
		color2 = colorCyan
	case 2:
		color2 = colorGreen
	case 3:
		color2 = colorYellow
	case 4:
		color2 = colorRed
	}
	fmt.Println(color2 + Logmsg + colorReset)
	fmt.Fprintln(file, Logmsg)
}

func Debug(msg string, args ...any) {
	createLog("DEBUG", 1, msg, args...)
}

func Info(msg string, args ...any) {
	createLog("INFO", 2, msg, args...)
}

func Warning(msg string, args ...any) {
	createLog("WARNING", 3, msg, args...)
}

func Error(msg string, args ...any) {
	createLog("ERROR", 4, msg, args...)
}

func init() {
	var err error
	file, err = os.OpenFile("Log.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		Error("Error with opening log file : ", err)
	}
}

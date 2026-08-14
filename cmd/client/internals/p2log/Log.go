package p2log

import (
	"P2Chat/cmd/client/internals/storage"
	"encoding/json" // for a more structured log file
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ANSI escape codes for colors
const (
	colorReset  = "\033[0m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorOrange = "\033[38;5;214m" // 256-color orange (no standard ANSI orange)
	colorRed    = "\033[31m"
	nameDir 	= "Log Files"
)

var encoder *json.Encoder

type log struct {
	Time 	string	`json:"time"`
	Level 	int		`json:"level"`
	Message	string	`json:"message"`
	Args    string	`json:"args"`
}

// Debug : details
// Info : normal events
// Warn : something go wrong
// Error : need attention

var initialized bool = false
var mu sync.Mutex

// create a log 
func createLog(prototype string, level int, msg string, args ...any) {

	mu.Lock()
	defer mu.Unlock()
	if !initialized {
		initializeLog()
	}

	timestamp := time.Now().Format("02-01-2006 15:04:05")
	argsMsg := fmt.Sprint(args...)
	Logmsg := fmt.Sprintf("[%s] [%s] %s %v", timestamp, prototype, msg, argsMsg)

	var color2 string
	switch level {
	case 1:
		color2 = colorCyan
	case 2:
		color2 = colorGreen
	case 3:
		color2 = colorOrange
	case 4:
		color2 = colorRed
	}

	// print in the console
	fmt.Println(color2 + Logmsg + colorReset)

	// create the JSON structure and write it on the file
	logMessage := log{
		Time:		timestamp,
		Level:		level,
		Message:	msg,
		Args: 		argsMsg,	
	}
	if encoder != nil {
		encoder.Encode(logMessage)
	}
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


// initialize the log file 
func initMessage(file *os.File) {
	timestamp := time.Now().Format("02-01-2006 15:04:05")
	message := fmt.Sprint("--- NEW OPENING LOG FILE ---\n--- TIME : ",timestamp," ---\n")
	fmt.Fprintf(file,message)
}


// initialize the FILE LOG 
func initializeLog() {
	var err error

	// opening the file
	dir := filepath.Join(storage.BasePath, nameDir)
	os.MkdirAll(dir, 0700)

	file, err := os.OpenFile(filepath.Join(dir, "log_console.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error with opening log file : ", err)
	}

	// initialize the JSON stream writer ( global variable )
	encoder = json.NewEncoder(file)

	// i notice in the file that the server and the file are opening again
	initMessage(file)

	initialized = true
}
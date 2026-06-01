package logger

import (
	"fmt"
	"log"
	"os"
	"rrcore/cmd/colors"
	"strconv"
)

// Debug defines whether debug mode is enabled
func getDebugValue() (bool, error) {
	var debugStr = os.Getenv("DEBUG")
	debug, err := strconv.ParseBool(debugStr)
	if err != nil {
		log.Fatalf("Invalid value for DEBUG. Must be true or false")
		return false, err
	}
	return debug, nil
}

var Debug, _ = getDebugValue()

// Profile holds the requested AWS profile name
var Profile = ""

// Region holds the requested AWS region name
var Region = ""

// Debugf prints messages for stdout only if Debug is true
func Debugf(message string, parts ...interface{}) {
	if Debug {
		fmt.Println(colors.Grey("DEBUG: " + fmt.Sprintf(message, parts...)))
	}
}

func Debugln(message string) {
	if Debug {
		fmt.Println(colors.Grey("DEBUG: " + fmt.Sprint(message)))
	}
}

func DebuglnBytes(message []byte) {
	if Debug {
		fmt.Println(colors.Grey(fmt.Sprintf("DEBUG: %s", message)))
	}
}

func Warnf(f string, args ...any) {
	log.Println(colors.Yellow(fmt.Sprintf(f, args...)))
}

func Errorln(message string) {
	log.Println(colors.Red(message))
}

func Errorf(f string, args ...any) {
	log.Println(colors.Red(fmt.Sprintf(f, args...)))
}

func Fatalf(f string, args ...any) {
	log.Fatalf("%s", colors.Red(fmt.Sprintf(f, args...)))
}

func Fatalln(message string) {
	log.Fatalln(colors.Red(message))
}

func SuccessMessageln(message string) {
	log.Println(colors.Green(message))
}

func SuccessMessagef(f string, args ...any) {
	log.Println(colors.Green(fmt.Sprintf(f, args...)))
}

package helper

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/chzyer/readline"
	"github.com/gookit/color"
	"github.com/nathan-fiscaletti/consolesize-go"
	"golang.org/x/term"
)

// IsTTY will be true if stdout is connected to a true terminal
var IsTTY bool

// isANSI will be true if console supports ANSI escape code. It is for Windows only.
var isANSI bool

// NoColour should be false if you want output to be coloured
var NoColour = false

// Max Retries to bet set as 3 by default
var maxRetries = 3

func init() {
	IsTTY = term.IsTerminal(int(os.Stdout.Fd()))
	isANSI = true
}

// Size returns the width and height of the console in characters
func Size() (int, int) {
	return consolesize.GetConsoleSize()
}

// CountLines returns the number of lines that would be taken up by the given string
func CountLines(input string) int {
	input = color.ClearCode(input)

	if input == "" {
		return 0
	}

	w, _ := Size()

	if w == 0 {
		return 0
	}

	count := 0
	for _, line := range strings.Split(input, "\n") {
		d := int(math.Ceil(float64(len([]rune(line))) / float64(w)))
		if d == 0 {
			d = 1
		}
		count += d
	}

	return count
}

// ClearLine removes all text from the current line and puts the cursor on the left
func ClearLine() {
	if IsTTY && isANSI {
		fmt.Print("\033[G\033[K")
	} else {
		fmt.Println()
	}
}

// ClearLines removes all text from the previous n lines (starting with the current line) and puts the cursor on the left
func ClearLines(n int) {
	if !IsTTY {
		return
	}

	for i := 0; i < n; i++ {
		ClearLine()
		if i < n-1 {
			if IsTTY && isANSI {
				fmt.Print("\033[F")
			}
		}
	}
}

// Ask prints the supplied prompt and then waits for user input which is returned as a string.
func Ask(prompt string) string {
	if !IsTTY {
		panic(errors.New("no interactive terminal detected; try running rrcore in interactive mode (e.g. without --yes)"))
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt: prompt + " ",
	})
	if err != nil {
		panic(fmt.Errorf("unable to get user input: %w", err))
	}

	answer, err := rl.Readline()
	if err != nil {
		panic(fmt.Errorf("unable to get user input: %w", err))
	}

	return strings.TrimSpace(answer)
}

// AskWithSelection prompts the user with interactive selection menu and then waits for user's selection which is returned as a string.
func AskWithSelection(prompt string, options []string) string {
	if !IsTTY {
		panic(errors.New("no interactive terminal detected; try running rrcore in interactive mode (e.g. without --yes)"))
	}
	if len(options) > 0 {
		var selected string
		promptObj := &survey.Select{
			Message: prompt,
			Options: options,
		}
		err := survey.AskOne(promptObj, &selected)
		if err != nil {
			log.Fatalf("Error getting selection: %v", err)
		}
		return selected
	}
	rl, err := readline.NewEx(&readline.Config{
		Prompt: prompt + " ",
	})
	if err != nil {
		panic(fmt.Errorf("unable to get user input: %w", err))
	}
	defer rl.Close()

	answer, err := rl.Readline()
	if err != nil {
		panic(fmt.Errorf("unable to get user input: %w", err))
	}

	return strings.TrimSpace(answer)
}

// Confirm asks the user for "y" or "n" and returns true if the response was "y".
// defaultYes is used to determine whether (y/N) or (Y/n) is displayed after the prompt.
func Confirm(defaultYes bool, prompt string) bool {
	extra := " (y/N)"

	if defaultYes {
		extra = " (Y/n)"
	}

	answer := Ask(prompt + extra)

	if strings.ToUpper(answer) == "Y" || (defaultYes && answer == "") {
		return true
	}

	return false
}

func IsValEmpty(val string) bool {
	return val == "<nil>" || val == ""
}

func GetNonEmptyInput(varName, val string) {
	attempts := 0
	for attempts < maxRetries && IsValEmpty(val) {
		val = Ask(fmt.Sprintf("%s cannot be empty. Please provide value for %s: ", varName, varName))
		os.Setenv(varName, val)
		attempts++
	}
	if IsValEmpty(val) {
		panic(fmt.Errorf("maximum attempts reached"))
	}
}

func ReplaceEnvVarVal(key, input string) string {
	keyVal := os.Getenv(key)
	return strings.ReplaceAll(input, fmt.Sprintf("$%s", key), keyVal)
}

func ReadTemplateFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read template file: %w", err)
	}
	return string(data), nil
}

func GetDeploymentTargetsType(deploymentTargets []string) (deploymentTargetsType string, isStandaloneDeployment bool) {
	for _, target := range deploymentTargets {
		if strings.HasPrefix(target, "r-") {
			deploymentTargetsType = "ROOT_OU"
		} else if strings.HasPrefix(target, "ou-") {
			deploymentTargetsType = "PARENT_OU"
		} else if regexp.MustCompile(`^\d{12}$`).MatchString(target) {
			isStandaloneDeployment = true
			deploymentTargetsType = "STANDALONE"
		}
	}
	return deploymentTargetsType, isStandaloneDeployment
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func RequireGuardDutyCentralLoggingBucket(deploymentRegions []string) bool {
	var optInRegionFound bool
	optInRegions := []string{
		"af-south-1",
		"ap-east-1",
		"ap-south-2",
		"ap-southeast-3",
		"ap-southeast-4",
		"ca-west-1",
		"eu-south-1",
		"eu-south-2",
		"eu-central-2",
		"me-south-1",
		"me-central-1",
		"il-central-1",
	}
	for _, region := range deploymentRegions {
		if contains(optInRegions, region) {
			optInRegionFound = true
			break
		}
	}
	if optInRegionFound {
		return false
	} else {
		return true
	}
}

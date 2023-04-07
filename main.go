// log-parse-agent listens for log parse/tail request from client and responds with the corresponding output.
// what application and log files to support is configured in the config file.
// the agent also supports sharing this config periodically to a central server (which becomes the client for this agent).
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/semaphore"
)

// config properties for the app supported by the agent.
type appConfiguration struct {
	App               string   `json:"app"`
	SearchTimeout     uint     `json:"search-timeout-minute"`
	PreMatchLinesMax  uint     `json:"pre-match-lines-max"`
	PostMatchLinesMax uint     `json:"post-match-lines-max"`
	Logs              []string `json:"logs"`
	Active            bool     `json:"active"`
}

// config properties supported by the agent
type LogAgentConfig struct {
	ServerURL                string             `json:"server-url"`
	NoOfConcurrentReqAllowed int                `json:"no-of-concurrent-req-allowed"`
	AgentHost                string             `json:"agent-host"`
	AgentPort                string             `json:"agent-port"`
	AgentInfoPostInterval    int                `json:"agent-info-post-interval-minutes"`
	AppsSupported            []appConfiguration `json:"apps-supported"`
}

// api output data structure
type searchResult struct {
	Data []string `json:"data"`
}

// api input data structure
type apiInputData struct {
	App            string   `json:"app" validate:"required"`
	SearchText     string   `json:"search-text" validate:"required"`
	IsRegEx        bool     `json:"is-regex"`
	PreMatchLines  uint     `json:"pre-match-lines" validate:"gte=0,lte=9"`
	PostMatchLines uint     `json:"post-match-lines" validate:"gte=0,lte=9"`
	LogFiles       []string `json:"search-logs" validate:"required,min=1"`
	SearchTimeout  uint     `json:"search-timeout-minute"`
}

var agentConfig LogAgentConfig
var inputData apiInputData
var validate *validator.Validate
var cmdInProgress map[string]*exec.Cmd

// semaphore to control no. of concurrent req can be served
var sem semaphore.Weighted

func init() {
	//read config file
	var content []byte
	var err error
	if content, err = os.ReadFile("./config/agent-config.json"); err != nil {
		panic(err)
	}
	if err = json.Unmarshal(content, &agentConfig); err != nil {
		panic(err)
	}
	hostname, _ := os.Hostname()
	if strings.EqualFold(agentConfig.AgentHost, "") {
		agentConfig.AgentHost = hostname
	}
	log.Printf("Agent Config:%v\n", agentConfig)

	//initialize
	gin.SetMode(gin.ReleaseMode)
	cmdInProgress = make(map[string]*exec.Cmd)
	validate = validator.New()
	if agentConfig.AgentInfoPostInterval == 0 {
		//default to 30 minutes
		agentConfig.AgentInfoPostInterval = 30
	}
	if agentConfig.NoOfConcurrentReqAllowed == 0 {
		//default to 2
		agentConfig.NoOfConcurrentReqAllowed = 2
	}
	sem = *semaphore.NewWeighted(int64(agentConfig.NoOfConcurrentReqAllowed))

	//identify files for the given log file pattern (if any)
	for i, app := range agentConfig.AppsSupported {
		tmpLogs := []string{}
		for _, logFile := range app.Logs {
			if strings.Contains(logFile, "*") {
				if files, err := findLatestFileForGivenPattern(logFile); err == nil {
					tmpLogs = append(tmpLogs, files...)
				}
			} else {
				tmpLogs = append(tmpLogs, logFile)
			}
		}
		agentConfig.AppsSupported[i].Logs = tmpLogs
	}
	log.Printf("Agent Config Updated:%v\n", agentConfig)

	//scheduled task to post agent info periodically
	if !strings.EqualFold(agentConfig.ServerURL, "") {
		log.Printf("Posting Agent Config to Server:%s\n", agentConfig.ServerURL)
		go func() {
			for {
				postAgentInfo()
				time.Sleep(time.Duration(agentConfig.AgentInfoPostInterval) * time.Minute)
			}
		}()
	} else {
		log.Printf("No Server Configured for Agent Config Posting \n")
	}

}

func main() {
	//set API route
	router := gin.Default()

	//register global handlers to control concurrent request
	router.Use(checkAllowableConcurrentReq)

	router.GET("/api/logs/search/info", logSearchInfoHandler)
	router.POST("/api/logs/search/files", validateSearchInput, checkAppAndLogFilesSupported, findMatchFilesHandler)
	router.POST("/api/logs/search/lines", validateSearchInput, checkAppAndLogFilesSupported, findMatchLinesHandler)
	router.POST("/api/logs/tail/files", validateTailInput, checkAppAndLogFilesSupported, tailLogsHandler)
	router.POST("/api/logs/command/cancel", cmdCancelHandler)

	router.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Not found"})
	})

	log.Printf("***********Agent Started at:%s:%s\n", agentConfig.AgentHost, agentConfig.AgentPort)

	//RUN API SERVER
	router.Run(agentConfig.AgentHost + ":" + agentConfig.AgentPort)
}

// control no. of simultaneous requests
func checkAllowableConcurrentReq(c *gin.Context) {
	//if cancel operation request then ignore concurrent check
	if strings.EqualFold(c.Request.URL.Path, "/api/logs/command/cancel") {
		return
	}

	ctx, cancel := context.WithTimeout(context.TODO(), 1*time.Second)
	defer cancel()
	// Acquire the semaphore
	err := sem.Acquire(ctx, 1)
	if err != nil {
		//full and time out
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "no. of concurrent requests allowed exhausted, please wait for previous operations to finish!"})
		log.Printf("\nAPI:%s, Error:%v\n", c.Request.URL.Path, err)
		c.Abort()
		return
	}
	defer sem.Release(1)
	//do work
	c.Next()
}

// API handler to return LogAgentInfo
func logSearchInfoHandler(c *gin.Context) {
	c.JSON(http.StatusOK, agentConfig)
}

// API input validator for log search
func validateSearchInput(c *gin.Context) {
	//fetch input data from request
	searchApp := strings.TrimSpace(c.Request.FormValue("search-app"))
	searchText := strings.TrimSpace(c.Request.FormValue("search-text"))
	searchFiles := c.Request.Form["search-files"]
	isRegEx := false

	isRegExTmp := strings.TrimSpace(c.Request.FormValue("is-regex"))
	if strings.EqualFold(isRegExTmp, "is-regex") {
		isRegEx = true
	}
	preMatchLines := strings.TrimSpace(c.Request.FormValue("pre-match-lines"))
	postMatchLines := strings.TrimSpace(c.Request.FormValue("post-match-lines"))
	preMatchTmp, _ := strconv.Atoi(preMatchLines)
	postMatchTmp, _ := strconv.Atoi(postMatchLines)

	//populate variable, will be used validator & then by next handler
	//note: searchTimeout is not sent by api requestor, it is used internally
	inputData = apiInputData{App: searchApp, SearchText: searchText, LogFiles: searchFiles, IsRegEx: isRegEx, PreMatchLines: uint(preMatchTmp), PostMatchLines: uint(postMatchTmp)}
	log.Printf("API:%s, InputData:%v \n", c.Request.URL.Path, inputData)

	//perform validation
	if errs := validate.Struct(inputData); errs != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errs.Error()})
		log.Printf("API:%s, InputData:%v, Validation Failed:%s \n", c.Request.URL.Path, inputData, errs.Error())
		c.Abort()
		return
	}

	c.Set("InputData", inputData)
}

// app specific validation
func checkAppAndLogFilesSupported(c *gin.Context) {
	data, exist := c.Get("InputData")
	if !exist {
		return
	}
	searchData := data.(apiInputData)

	searchApp := searchData.App
	searchFiles := searchData.LogFiles
	preMatchLines := searchData.PreMatchLines
	postMatchLines := searchData.PostMatchLines

	var appFound appConfiguration
	for _, v := range agentConfig.AppsSupported {
		if strings.EqualFold(v.App, searchApp) && v.Active {
			appFound = v
			for _, f := range searchFiles {
				if !slices.Contains(v.Logs, f) {
					//found log file which is not supported
					msg := fmt.Sprintf("Input Log file:%s not supported, [%v] ", f, v.Logs)
					c.JSON(http.StatusBadRequest, gin.H{"error": msg})
					log.Printf("API:%s, InputData:%v, Validation Failed:%s \n", c.Request.URL.Path, inputData, msg)
					c.Abort()
					return
				}
			}

			//at this point app and logs files matched
			if preMatchLines > appFound.PreMatchLinesMax {
				inputData.PreMatchLines = 0
			}
			if postMatchLines > appFound.PostMatchLinesMax {
				inputData.PostMatchLines = 0
			}
			inputData.SearchTimeout = appFound.SearchTimeout
			c.Set("InputData", inputData)

			return
		}
	}

	msg := "Input App is not supported, " + searchApp
	c.JSON(http.StatusBadRequest, gin.H{"error": msg})
	log.Printf("API:%s, InputData:%v, Validation Failed:%s \n", c.Request.URL.Path, inputData, msg)
	c.Abort()
}

// API input validator for log search
func validateTailInput(c *gin.Context) {
	searchApp := strings.TrimSpace(c.Request.FormValue("search-app"))
	logFile := strings.TrimSpace(c.Request.FormValue("search-file"))
	log.Printf("API:%s, InputData:%s, %s \n", c.Request.URL.Path, searchApp, logFile)

	if errs := validate.Var(searchApp, "required"); errs != nil {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(errs.Error()))
		log.Printf("API:%s, InputData:%v, Validation Failed:%s \n", c.Request.URL.Path, inputData, errs.Error())
		c.Abort()
		return
	}
	if errs := validate.Var(logFile, "required"); errs != nil {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(errs.Error()))
		log.Printf("API:%s, InputData:%v, Validation Failed:%s \n", c.Request.URL.Path, inputData, errs.Error())
		c.Abort()
		return
	}

	inputData = apiInputData{App: searchApp, LogFiles: []string{logFile}}
	c.Set("InputData", inputData)
}

// API handler for grep files match
func findMatchFilesHandler(c *gin.Context) {
	data, exist := c.Get("InputData")
	if !exist {
		return
	}
	searchData := data.(apiInputData)

	cmdKey := "grep" + strings.Join(searchData.LogFiles, "")
	if isCmdAlreadyInProgress(cmdKey) {
		msg := "Command already in-progress:" + cmdKey
		log.Printf("%s\n", msg)
		c.JSON(http.StatusOK, msg)
		return
	}

	op, err := findMatchFileNames(cmdKey, searchData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Printf("API:%s, Error:%s \n", c.Request.URL.Path, err.Error())
		return
	}
	c.JSON(http.StatusOK, op)
}

// API handler for grep lines match
func findMatchLinesHandler(c *gin.Context) {
	data, exist := c.Get("InputData")
	if !exist {
		return
	}
	searchData := data.(apiInputData)

	cmdKey := "grep-l" + strings.Join(searchData.LogFiles, "")
	if isCmdAlreadyInProgress(cmdKey) {
		msg := "Command already in-progress:" + cmdKey
		log.Printf("%s \n", msg)
		c.JSON(http.StatusOK, msg)
		return
	}

	err := findMatchLines(cmdKey, searchData, c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Printf("API:%s, Error:%s \n", c.Request.URL.Path, err.Error())
	}
}

// API handler for log tail
func tailLogsHandler(c *gin.Context) {
	data, exist := c.Get("InputData")
	if !exist {
		return
	}
	searchData := data.(apiInputData)

	searchApp := searchData.App
	logFile := searchData.LogFiles[0]

	for _, v := range agentConfig.AppsSupported {
		if strings.EqualFold(v.App, searchApp) && v.Active {
			if !slices.Contains(v.Logs, logFile) {
				msg := "Input file not supported, " + logFile
				c.JSON(http.StatusBadRequest, gin.H{"error": msg})
				log.Printf("API:%s, InputData:%v, Validation Failed:%s \n", c.Request.URL.Path, inputData, msg)
				return
			}
			//app and log file supported

			cmdKey := "tail" + logFile
			if isCmdAlreadyInProgress(cmdKey) {
				msg := "Command already in-progress:" + cmdKey
				log.Printf("%s \n", msg)
				c.JSON(http.StatusOK, msg)
				return
			}

			err := tailLogs(cmdKey, searchData, c)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				log.Printf("API:%s, Error:%s \n", c.Request.URL.Path, err.Error())
			}
		}
	}
}

// API - to cancel previous operation
func cmdCancelHandler(c *gin.Context) {
	cmdKey := strings.TrimSpace(c.Request.FormValue("cmd-key"))
	log.Printf("API:%s, InputData:%s \n", c.Request.URL.Path, cmdKey)

	if err := validate.Var(cmdKey, "required"); err != nil {
		log.Printf("API:%s, InputData:%v, Validation Failed:%s \n", c.Request.URL.Path, inputData, err.Error())
	}
	if cmd, ok := cmdInProgress[cmdKey]; ok {
		log.Printf("Found in-progress, cmd-key:%s \n", cmdKey)
		delete(cmdInProgress, cmdKey)
		cmd.Cancel()
		log.Printf("Cancelled in-progress, cmd-key:%s \n", cmdKey)
	}
}

// handler to find latest file for the given pattern
// find latest file for the given pattern
func findLatestFileForGivenPattern(filePattern string) ([]string, error) {
	filesFound := []string{}

	//build command
	command := "bash"
	args := []string{"-c", "ls -lt " + filePattern}
	ctx := context.Background()
	timeOutDuration := 1 * time.Minute
	ctx, cancel := context.WithTimeout(ctx, timeOutDuration)
	defer cancel()

	//execute
	log.Printf("Executing... cmd:%s , args:%v \n", command, args)
	cmd := exec.CommandContext(ctx, command, args...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error:%s, Executing... cmd:%s , args:%v \n", err.Error(), command, args)
		return filesFound, err
	}

	op := string(out)
	tmp := strings.Split(op, "\n")
	log.Printf("Success!!, Executing... cmd:%s , args:%v , output:%s, parse:%v \n", command, args, op, tmp)

	if (len(tmp)) > 0 {
		tmp = strings.Split(tmp[0], " ")
		log.Printf("%v\n", tmp)
		if len(tmp) > 0 {
			fileName := tmp[len(tmp)-1]
			log.Printf("%s\n", fileName)
			filesFound = append(filesFound, fileName)
		}
	}
	return filesFound, nil
}

// find matched file names
func findMatchFileNames(cmdKey string, searchData apiInputData) (searchResult, error) {
	cmd := "grep"
	args := buildGrepArgs(searchData.SearchText, true, searchData.IsRegEx, searchData.PreMatchLines, searchData.PostMatchLines, searchData.LogFiles)
	log.Printf("Executing request for cmd:%s, args:%v \n", cmd, args)
	op, err := executeOSCommand(cmdKey, cmd, args, searchData.SearchTimeout)
	if err != nil {
		return searchResult{}, err
	}

	filesFound := strings.Split(op, "\n")
	//remove last file if blank
	if len(filesFound) > 0 {
		if strings.EqualFold(filesFound[len(filesFound)-1], "") {
			filesFound = filesFound[0 : len(filesFound)-1]
		}
	}

	return searchResult{Data: filesFound}, nil
}

// find matched lines
func findMatchLines(cmdKey string, searchData apiInputData, c *gin.Context) error {
	cmd := "grep"
	args := buildGrepArgs(searchData.SearchText, false, searchData.IsRegEx, searchData.PreMatchLines, searchData.PostMatchLines, searchData.LogFiles)
	log.Printf("Executing request for cmd:%s, args:%v \n", cmd, args)
	err := executeOSCommandAndRender(cmdKey, cmd, args, searchData.SearchTimeout, c)
	return err
}

// find matched lines
func tailLogs(cmdKey string, searchData apiInputData, c *gin.Context) error {
	cmd := "tail"
	args := []string{}
	args = append(args, "-f")
	args = append(args, searchData.LogFiles[0])
	log.Printf("Executing request for cmd:%s, args:%v \n", cmd, args)
	//set timeout 1 minute
	err := executeOSCommandAndRender(cmdKey, cmd, args, searchData.SearchTimeout, c)
	return err
}

// build grep command options
func buildGrepArgs(searchText string, onlyListing, isRegEx bool, preMatchLines, postMatchLines uint, files []string) []string {
	args := []string{}
	if onlyListing {
		args = append(args, "-l")
	} else {
		if isRegEx {
			args = append(args, "-E")
		}
		if preMatchLines != 0 {
			args = append(args, "-B")
			args = append(args, strconv.FormatUint(uint64(preMatchLines), 10))
		}
		if postMatchLines != 0 {
			args = append(args, "-A")
			args = append(args, strconv.FormatUint(uint64(postMatchLines), 10))
		}
	}
	args = append(args, searchText)
	args = append(args, files...)
	return args
}

// execute os command - grep for search
func executeOSCommand(cmdKey, command string, args []string, timeout uint) (string, error) {
	ctx := context.Background()
	var timeOutDuration time.Duration
	timeOutDuration, err := time.ParseDuration(strconv.FormatUint(uint64(timeout), 10) + "m")
	if err != nil {
		timeOutDuration = 1 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeOutDuration)
	defer cancel()

	//execute
	log.Printf("Executing... cmd:%s , args:%v \n", command, args)
	cmd := exec.CommandContext(ctx, command, args...)

	cmdInProgress[cmdKey] = cmd
	out, err := cmd.CombinedOutput()
	delete(cmdInProgress, cmdKey)
	if err != nil {
		log.Printf("Error:%s, Executing... cmd:%s , args:%v \n", err.Error(), command, args)
		return "", err
	}

	log.Printf("Success!!, Executing... cmd:%s , args:%v \n", command, args)
	return string(out), nil
}

// execute os command - with streaming and output rendering
func executeOSCommandAndRender(cmdKey, command string, args []string, timeout uint, c *gin.Context) error {
	ctx := context.Background()
	var timeOutDuration time.Duration
	timeOutDuration, err := time.ParseDuration(strconv.FormatUint(uint64(timeout), 10) + "m")
	if err != nil {
		timeOutDuration = 1 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeOutDuration)
	defer cancel()

	//execute
	log.Printf("Executing... cmd:%s , args:%v \n", command, args)
	cmd := exec.CommandContext(ctx, command, args...)

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Error:%s, Executing... cmd:%s , args:%v \n", err.Error(), command, args)
		return err
	}

	err = cmd.Start()
	if err != nil {
		log.Printf("Error:%s, Executing... cmd:%s , args:%v \n", err.Error(), command, args)
		return err
	}

	cmdInProgress[cmdKey] = cmd
	opChan := make(chan string)
	go func(stdOut io.ReadCloser) {
		defer close(opChan)
		scanner := bufio.NewScanner(stdOut)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			line := scanner.Text()
			opChan <- line
		}

	}(stdOut)

	//stream the output
	//write first line as cmdKey.
	c.Writer.Write([]byte(cmdKey + "\n"))
	//then stream the data
	c.Stream(func(w io.Writer) bool {
		if msg, ok := <-opChan; ok {
			outputBytes := bytes.NewBufferString(msg)
			c.Writer.Write(append(outputBytes.Bytes(), []byte("\n")...))
			return true
		}
		return false
	})

	cmd.Wait()
	log.Printf("Success!!, Executing... cmd:%s , args:%v \n", command, args)
	delete(cmdInProgress, cmdKey)

	return nil
}

func isCmdAlreadyInProgress(cmd string) bool {
	if _, ok := cmdInProgress[cmd]; ok {
		return true
	}
	return false
}

// post Agent Info
func postAgentInfo() {
	payloadBuf := new(bytes.Buffer)
	json.NewEncoder(payloadBuf).Encode(agentConfig)
	h := http.Client{}
	req, err := http.NewRequest("POST", agentConfig.ServerURL, payloadBuf)
	if err != nil {
		log.Printf("Error posting Agent Info: %s \n", err.Error())
		return
	}
	r, err := h.Do(req)
	if err != nil {
		log.Printf("Error posting Agent Info: %s \n", err.Error())
		return
	}
	defer r.Body.Close()
	bodyText, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Agent Info POST Response Parsing Error: %s \n", err.Error())
		return
	}
	log.Printf("Success posting Agent Info: %s \n", bodyText)
}

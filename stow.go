package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Info  bool `yaml:"Info"`
	Debug bool `yaml:"Debug"`
	Sigma struct {
		BaseUrl           string   `yaml:"BaseUrl"`
		ConvertAll        bool     `yaml:"ConvertAll"`
		ConvertCategories []string `yaml:"ConvertCategories"`
		ConvertProducts   []string `yaml:"ConvertProducts"`
		ConvertServices   []string `yaml:"ConvertServices"`
		RuleStatus        []string `yaml:"RuleStatus"`
		RulesRoot         string   `yaml:"RulesRoot"`
		SkipCategories    []string `yaml:"SkipCategories"`
		SkipIds           []string `yaml:"SkipIds"`
		SkipProducts      []string `yaml:"SkipProducts"`
		SkipServices      []string `yaml:"SkipServices"`
	} `yaml:"Sigma"`
	Wazuh struct {
		RulesFile   string `yaml:"RulesFile"`
		RuleIdFile  string `yaml:"RuleIdFile"`
		RuleIdStart int    `yaml:"RuleIdStart"`
		WriteRules  os.File
		Levels      struct {
			Informational int `yaml:"informational"`
			Low           int `yaml:"low"`
			Medium        int `yaml:"medium"`
			High          int `yaml:"high"`
			Critical      int `yaml:"critical"`
		} `yaml:"Levels"`
		Options struct {
			NoFullLog    bool     `yaml:"NoFullLog"`
			SigmaIdEmail []string `yaml:"SigmaIdEmail"`
			EmailAlert   bool     `yaml:"EmailAlert"`
			EmailLevels  []string `yaml:"EmailLevels"`
		} `yaml:"Options"`
		SidGrpMaps struct {
			SigmaIdToWazuhGroup        map[string]string `yaml:"SigmaIdToWazuhGroup"`
			SigmaIdToWazuhId           map[string]string `yaml:"SigmaIdToWazuhId"`
			ProductServiceToWazuhGroup map[string]string `yaml:"ProductServiceToWazuhGroup"`
			ProductServiceToWazuhId    map[string]string `yaml:"ProductServiceToWazuhId"`
		} `yaml:"SidGrpMaps"`
		FieldMaps map[string]map[string]string `yaml:"FieldMaps"`
		XmlRules  WazuhGroup
	} `yaml:"Wazuh"`
	// OR logic can force the creation of multiple Wazuh rules
	// Because of this we need to track Sigma to Wazuh rule ids between runs
	Ids struct {
		PreviousUsed []int            // Wazuh ids used in previous runs
		CurrentUsed  []int            // array of all used Wazuh IDs this run
		SigmaToWazuh map[string][]int // dict of sigma id to wazuh ids
	}
}

func (c *Config) getSigmaRules(path string, f os.FileInfo, err error) error {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	if !f.IsDir() && strings.HasSuffix(path, ".yml") {
		ReadYamlFile(path, c)
	}
	return nil
}

func initPreviousUsed(c *Config) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	for _, ids := range c.Ids.SigmaToWazuh {
		c.Ids.PreviousUsed = append(c.Ids.PreviousUsed, ids...)
	}
}

func InitConfig() *Config {
	c := &Config{
		Ids: struct {
			PreviousUsed []int
			CurrentUsed  []int
			SigmaToWazuh map[string][]int
		}{
			SigmaToWazuh: make(map[string][]int),
		},
	}

	// Load Sigma and Wazuh config for rule processing
	data, err := ioutil.ReadFile("./config.yaml")
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
	}
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
	}

	// Load Sigma ID to Wazuh ID mappings
	data, err = ioutil.ReadFile(c.Wazuh.RuleIdFile)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
		data = nil
	}
	err = yaml.Unmarshal(data, c.Ids.SigmaToWazuh)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
		data = nil
	}
	initPreviousUsed(c)
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	return c
}

type SigmaRule struct {
	Title       string   `yaml:"title"`
	ID          string   `yaml:"id"`
	Status      string   `yaml:"status"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references"`
	Author      string   `yaml:"author"`
	Date        string   `yaml:"date"`
	Modified    string   `yaml:"modified"`
	Tags        []string `yaml:"tags"`
	LogSource   struct {
		Product  string `yaml:"product"`
		Service  string `yaml:"service"`
		Category string `yaml:"category"`
	} `yaml:"logsource"`
	Detection      interface{} `yaml:"detection"`
	FalsePositives []string    `yaml:"falsepositives"`
	Level          string      `yaml:"level"`
}

// outer rules xml
type WazuhGroup struct {
	XMLName xml.Name    `xml:"group"`
	Name    string      `xml:"name,attr"`
	Header  xml.Comment `xml:",comment"`
	Rules   []WazuhRule `xml:"rule"`
}

type Field struct {
	Name   string `xml:"name,attr"`
	Negate string `xml:"negate,attr"`
	Type   string `xml:"type,attr"`
	Value  string `xml:",chardata"`
}

// per rule xml
type WazuhRule struct {
	XMLName xml.Name `xml:"rule"`
	ID      string   `xml:"id,attr"`
	Level   string   `xml:"level,attr"`
	Info    struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"info,omitempty"`
	Author           xml.Comment `xml:",comment"`
	SigmaDescription xml.Comment `xml:",comment"`
	Date             xml.Comment `xml:",comment"`
	Modified         xml.Comment `xml:",comment"`
	Status           xml.Comment `xml:",comment"`
	SigmaID          xml.Comment `xml:",comment"`
	Mitre            struct {
		IDs []string `xml:"id,omitempty"`
	} `xml:"mitre,omitempty"`
	Description string   `xml:"description"`
	Options     []string `xml:"options,omitempty"`
	Groups      string   `xml:"group,omitempty"`
	IfSid       string   `xml:"if_sid,omitempty"`
	IfGroup     string   `xml:"if_group,omitempty"`
	Fields      []Field  `xml:"field"`
}

func AddToMapStrToInts(c *Config, sigmaId string, wazuhId int) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	// If the key doesn't exist, add it to the map with a new slice
	if _, ok := c.Ids.SigmaToWazuh[sigmaId]; !ok {
		c.Ids.SigmaToWazuh[sigmaId] = []int{wazuhId}
		return
	}
	// If the key exists, append to the slice
	c.Ids.SigmaToWazuh[sigmaId] = append(c.Ids.SigmaToWazuh[sigmaId], wazuhId)
}

func TrackIdMaps(sigmaId string, c *Config) string {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	// has this Sigma rule been converted previously, reuse its Wazuh rule IDs
	if ids, ok := c.Ids.SigmaToWazuh[sigmaId]; ok {
		for _, id := range ids {
			if !slices.Contains(c.Ids.CurrentUsed, id) {
				c.Ids.CurrentUsed = append(c.Ids.CurrentUsed, id)
				return strconv.Itoa(id)
			}
		}
	}
	// new Sigma rule, find an unused Wazuh rule ID
	for slices.Contains(c.Ids.PreviousUsed, c.Wazuh.RuleIdStart) ||
		slices.Contains(c.Ids.CurrentUsed, c.Wazuh.RuleIdStart) {
		c.Wazuh.RuleIdStart++
	}
	AddToMapStrToInts(c, sigmaId, c.Wazuh.RuleIdStart)
	c.Ids.CurrentUsed = append(c.Ids.CurrentUsed, c.Wazuh.RuleIdStart)
	return strconv.Itoa(c.Wazuh.RuleIdStart)
}

func GetLevel(sigmaLevel string, c *Config) int {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	switch strings.ToLower(sigmaLevel) {
	case "informational":
		return c.Wazuh.Levels.Informational
	case "low":
		return c.Wazuh.Levels.Low
	case "medium":
		return c.Wazuh.Levels.Medium
	case "high":
		return c.Wazuh.Levels.High
	case "critical":
		return c.Wazuh.Levels.Critical
	default:
		return c.Wazuh.Levels.Informational
	}
}

func GetIfGrpSid(sigma *SigmaRule, c *Config) (string, string) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	// Get Wazuh if_group or if_sids dependencies for converted rules
	switch {
	case c.Wazuh.SidGrpMaps.SigmaIdToWazuhGroup[sigma.ID] != "":
		return "grp", c.Wazuh.SidGrpMaps.SigmaIdToWazuhGroup[sigma.ID]
	case c.Wazuh.SidGrpMaps.SigmaIdToWazuhId[sigma.ID] != "":
		return "sid", c.Wazuh.SidGrpMaps.SigmaIdToWazuhId[sigma.ID]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Service] != "":
		return "grp", c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Service]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Product] != "":
		return "grp", c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Product]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Service] != "":
		return "sid", c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Service]
	case c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Product] != "":
		return "sid", c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Product]
	default:
		return "sid", ""
	}
}

func GetGroups(sigma *SigmaRule, c *Config) string {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	var groups string
	if sigma.LogSource.Category != "" {
		groups = sigma.LogSource.Category + ","
	}
	if sigma.LogSource.Product != "" {
		groups += sigma.LogSource.Product + ","
	}
	if sigma.LogSource.Service != "" {
		groups += sigma.LogSource.Service + ","
	}
	return groups
}

func GetOptions(sigma *SigmaRule, c *Config) []string {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	var options []string
	if c.Wazuh.Options.NoFullLog {
		options = append(options, "no_full_log")

	}
	if c.Wazuh.Options.EmailAlert &&
		(slices.Contains(c.Wazuh.Options.SigmaIdEmail, sigma.ID) ||
			slices.Contains(c.Wazuh.Options.EmailLevels, sigma.Level)) {
		options = append(options, "alert_by_email")
	}
	return options
}

func GetFields(sigma *SigmaRule, c *Config) []Field {
	var field Field
	var fields []Field
	fields = append(fields, field)
	return fields
}

func BuildRule(sigma *SigmaRule, url string, c *Config) WazuhRule {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	var rule WazuhRule

	rule.ID = TrackIdMaps(sigma.ID, c)
	rule.Level = strconv.Itoa(GetLevel(sigma.Level, c))
	rule.Description = sigma.Title
	rule.Info.Type = "link"
	rule.Info.Value = url
	// sometimes we see "--" in sigma fields which will break xml when in comments
	rule.Author = xml.Comment("     Author: " + strings.Replace(sigma.Author, "--", "-", -1))
	rule.SigmaDescription = xml.Comment("Description: " + strings.Replace(sigma.Description, "--", "-", -1))
	rule.Date = xml.Comment("    Created: " + strings.Replace(sigma.Date, "--", "-", -1))
	rule.Modified = xml.Comment("   Modified: " + strings.Replace(sigma.Modified, "--", "-", -1))
	rule.Status = xml.Comment("     Status: " + strings.Replace(sigma.Status, "--", "-", -1))
	rule.SigmaID = xml.Comment("   Sigma ID: " + strings.Replace(sigma.ID, "--", "-", -1))
	rule.Mitre.IDs = sigma.Tags
	rule.Options = GetOptions(sigma, c)
	rule.Groups = GetGroups(sigma, c)
	ifType, value := GetIfGrpSid(sigma, c)
	if ifType == "grp" {
		rule.IfGroup = value
	} else {
		rule.IfSid = value
	}
	rule.Fields = GetFields(sigma, c)

	return rule
}

func SkipSigmaRule(sigma *SigmaRule, c *Config) bool {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	switch {
	case slices.Contains(c.Sigma.SkipIds, strings.ToLower(sigma.ID)):
		LogIt(INFO, "Skip Sigma rule ID: "+sigma.ID, nil, c.Info, c.Debug)
		return true
	case !slices.Contains(c.Sigma.RuleStatus, strings.ToLower(sigma.Status)):
		LogIt(INFO, "Skip Sigma rule status: "+sigma.ID, nil, c.Info, c.Debug)
		return true
	case c.Sigma.ConvertAll:
		return false
	case slices.Contains(c.Sigma.ConvertCategories, strings.ToLower(sigma.LogSource.Category)):
		return false
	case slices.Contains(c.Sigma.ConvertServices, strings.ToLower(sigma.LogSource.Service)):
		return false
	case slices.Contains(c.Sigma.ConvertProducts, strings.ToLower(sigma.LogSource.Product)):
		return false
	default:
		LogIt(INFO, "Skip Sigma rule default: "+sigma.ID, nil, c.Info, c.Debug)
		return true
	}
}

func GetTopLevelLogicCondition(sigma SigmaRule) map[string]interface{} {
	detections := make(map[string]interface{})
	v := reflect.ValueOf(sigma.Detection)
	for _, k := range v.MapKeys() {
		value := v.MapIndex(k)
		key := k.Interface().(string)
		detections[key] = value.Interface()
	}
	return detections
}

func PrintValues(detections map[string]interface{}) {
	for k, v := range detections {
		fmt.Printf("%v - %v\n", k, v)
	}
}

// Create tokens out of Sigma condition for better logic parsing
func fixupCondition(condition interface{}) []string {
	c := condition.(string)
	c = strings.Replace(c, "1 of them", "1_of", -1)
	c = strings.Replace(c, "all of them", "all_of", -1)
	c = strings.Replace(c, "1 of", "1_of", -1)
	c = strings.Replace(c, "all of", "all_of", -1)
	c = strings.Replace(c, "(", " ( ", -1)
	c = strings.Replace(c, ")", " ) ", -1)
	t := strings.Split(c, " ")
	// remove empty array members
	var result []string
	for _, str := range t {
		if str != "" {
			result = append(result, str)
		}
	}
	return result
}

// Propagate nots found before a left paren
// revisit logic
func propagateNots(tokens []string) []string {
	newTokens := []string{}
	notFound := false
	level := 0
	for _, t := range tokens {
		if t == "not" {
			notFound = !notFound
			continue
		} else if t == "(" {
			level++
		} else if t == ")" {
			level--
			if level == 0 {
				notFound = false
			}
		} else if (notFound && level > 0) && (t != "or" && t != "and") {
			t = "not " + t
		} else if notFound && level < 1 {
			newTokens =  append(newTokens, "not")
			notFound = false
		}
		newTokens = append(newTokens, t)
	}
	return newTokens
}

func ReadYamlFile(path string, c *Config) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
		return
	}
	LogIt(INFO, path, nil, c.Info, c.Debug)
	p := strings.Split(path, "/rules")
	var url string
	if len(p) > 1 {
		url = c.Sigma.BaseUrl + p[1]
	} else {
		url = c.Sigma.BaseUrl
	}
	var sigmaRule SigmaRule

	err = yaml.Unmarshal(data, &sigmaRule)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
		return
	}

	if SkipSigmaRule(&sigmaRule, c) {
		return
	}

	detections := GetTopLevelLogicCondition(sigmaRule)
	PrintValues(detections)
	detection := fixupCondition(detections["condition"])
	fmt.Printf("%v", detection)
	detection = propagateNots(detection)
	fmt.Printf("\n%v\n%v\n\n", detections["condition"], detection)

	rule := BuildRule(&sigmaRule, url, c)
	c.Wazuh.XmlRules.Rules = append(c.Wazuh.XmlRules.Rules, rule)
}

func WriteWazuhXmlRules(c *Config) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	// Create an XML encoder that writes to the file
	enc := xml.NewEncoder(&c.Wazuh.WriteRules)
	enc.Indent("", "  ")

	// Encode the rule struct to XML
	if err := enc.Encode(c.Wazuh.XmlRules); err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
	}
	if _, err := c.Wazuh.WriteRules.WriteString("\n"); err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
	}
}

func main() {
	c := InitConfig()
	c.Info, c.Debug = getArgs(os.Args, c)
	LogIt(DEBUG, "", nil, c.Info, c.Debug)

	// Convert rules
	file, err := os.Create(c.Wazuh.RulesFile)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
		return
	}
	c.Wazuh.WriteRules = *file
	defer file.Close()

	err = filepath.Walk(c.Sigma.RulesRoot, c.getSigmaRules)
	if err != nil {
		LogIt(ERROR, c.Sigma.RulesRoot, err, c.Info, c.Debug)
	}

	// build our xml rule file and write it
	c.Wazuh.XmlRules.Name = "sigma,"
	c.Wazuh.XmlRules.Header = xml.Comment("\n\tAuthor: Brian Kellogg\n\tSigma: https://github.com/SigmaHQ/sigma\n\tWazuh: https://wazuh.com\n\tAll Sigma rules licensed under DRL: https://github.com/SigmaHQ/Detection-Rule-License ")
	WriteWazuhXmlRules(c)

	// Convert map to json
	jsonData, err := json.Marshal(c.Ids.SigmaToWazuh)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
	}
	// Write JSON data to a file
	err = ioutil.WriteFile(c.Wazuh.RuleIdFile, jsonData, 0644)
	if err != nil {
		LogIt(ERROR, "", err, c.Info, c.Debug)
	}
}

/*****************************************************************
UTILITY FUNCTIONS
*/

func getArgs(args []string, c *Config) (bool, bool) {
	LogIt(DEBUG, "", nil, c.Info, c.Debug)
	if len(args) == 1 {
		return c.Info, c.Debug
	}
	infoArgs := []string{"-i", "--info"}
	debugArgs := []string{"-d", "--debug"}
	for _, arg := range args {
		switch {
		case slices.Contains(infoArgs, arg):
			c.Info = true
		case slices.Contains(debugArgs, arg):
			c.Info = true
			c.Debug = true
		}
	}
	return c.Info, c.Debug
}

const DEBUG = "debug"
const INFO = "info"
const WARN = "warn"
const ERROR = "error"

// Get function name for debugging
func printPreviousFunctionName() string {
	pc, _, _, _ := runtime.Caller(2) // 2 steps up the call stack
	functionPath := runtime.FuncForPC(pc).Name()
	return functionPath
}

func LogIt(level string, msg string, err error, info bool, debug bool) {
	log.SetOutput(os.Stdout)
	switch level {
	case ERROR:
		log.Printf("ERROR: %v - %v", msg, err)
	case WARN:
		log.Printf(" WARN: %v", msg)
	case INFO:
		if info {
			log.Printf(" INFO: %v", msg)
		}
	case DEBUG:
		if debug {
			function := printPreviousFunctionName()
			if msg != "" {
				log.Printf("DEBUG: %v - %v", function, msg)
			} else {
				log.Printf("DEBUG: %v", function)
			}
		}
	}
}

// func contains(slice []string, str string) bool {
// 	for _, v := range slice {
// 		if v == str {
// 			return true
// 		}
// 	}
// 	return false
// }

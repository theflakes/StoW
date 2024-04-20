package main

import (
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

const INFO = "info"
const WARN = "warn"
const ERROR = "error"

func LogIt(level string, msg string, err error, debug bool) {
	log.SetOutput(os.Stdout)
	switch level {
	case ERROR:
		log.Printf("ERROR: %v - %v", msg, err)
	case "warnging":
		log.Printf(" WARN: %v", msg)
	case "info":
		if debug {
			log.Printf(" INFO: %v", msg)
		}
	}
}

type Config struct {
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
	if !f.IsDir() && strings.HasSuffix(path, ".yml") {
		ReadYamlFile(path, c)
	}
	return nil
}

func initPreviousUsed(c *Config) {
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
		LogIt(ERROR, "", err, c.Debug)
	}
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		LogIt(ERROR, "", err, c.Debug)
	}

	// Load Sigma ID to Wazuh ID mappings
	data, err = ioutil.ReadFile(c.Wazuh.RuleIdFile)
	if err != nil {
		LogIt(ERROR, "", err, c.Debug)
		data = nil
	}
	err = yaml.Unmarshal(data, c.Ids.SigmaToWazuh)
	if err != nil {
		LogIt(ERROR, "", err, c.Debug)
		data = nil
	}
	initPreviousUsed(c)

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
	Fields      []struct {
		Name   string `xml:"name,attr"`
		Negate string `xml:"negate,attr"`
		Type   string `xml:"type,attr"`
		Value  string `xml:",chardata"`
	} `xml:"field"`
}

func AddToMapStrToInts(c *Config, sigmaId string, wazuhId int) {
	// If the key doesn't exist, add it to the map with a new slice
	if _, ok := c.Ids.SigmaToWazuh[sigmaId]; !ok {
		c.Ids.SigmaToWazuh[sigmaId] = []int{wazuhId}
		return
	}
	// If the key exists, append to the slice
	c.Ids.SigmaToWazuh[sigmaId] = append(c.Ids.SigmaToWazuh[sigmaId], wazuhId)
}

func TrackIdMaps(sigmaId string, c *Config) string {
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
	// Get Wazuh if_group or if_sids dependencies for converted rules
	if c.Wazuh.SidGrpMaps.SigmaIdToWazuhGroup[sigma.ID] != "" {
		return "grp", c.Wazuh.SidGrpMaps.SigmaIdToWazuhGroup[sigma.ID]

	} else if c.Wazuh.SidGrpMaps.SigmaIdToWazuhId[sigma.ID] != "" {
		return "sid", c.Wazuh.SidGrpMaps.SigmaIdToWazuhId[sigma.ID]

	} else if c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Service] != "" {
		return "grp", c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Service]

	} else if c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Product] != "" {
		return "grp", c.Wazuh.SidGrpMaps.ProductServiceToWazuhGroup[sigma.LogSource.Product]

	} else if c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Service] != "" {
		return "sid", c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Service]

	} else if c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Product] != "" {
		return "sid", c.Wazuh.SidGrpMaps.ProductServiceToWazuhId[sigma.LogSource.Product]
	}

	return "sid", ""
}

func GetGroups(sigma *SigmaRule) string {
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

func BuildRule(sigma *SigmaRule, url string, c *Config) WazuhRule {
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
	rule.Groups = GetGroups(sigma)
	ifType, value := GetIfGrpSid(sigma, c)
	if ifType == "grp" {
		rule.IfGroup = value
	} else {
		rule.IfSid = value
	}

	return rule
}

func SkipSigmaRule(sigma *SigmaRule, c *Config) bool {
	if slices.Contains(c.Sigma.SkipIds, strings.ToLower(sigma.ID)) {
		LogIt(INFO, "Skip Sigma rule ID: "+sigma.ID, nil, c.Debug)
		return true
	}
	if !slices.Contains(c.Sigma.RuleStatus, strings.ToLower(sigma.Status)) {
		LogIt(INFO, "Skip Sigma rule status: "+sigma.ID, nil, c.Debug)
		return true
	}
	if c.Sigma.ConvertAll {
		return false
	}
	if slices.Contains(c.Sigma.ConvertCategories, strings.ToLower(sigma.LogSource.Category)) {
		return false
	}
	if slices.Contains(c.Sigma.ConvertServices, strings.ToLower(sigma.LogSource.Service)) {
		return false
	}
	if slices.Contains(c.Sigma.ConvertProducts, strings.ToLower(sigma.LogSource.Product)) {
		return false
	}
	LogIt(INFO, "Skip Sigma rule default: "+sigma.ID, nil, c.Debug)
	return true
}

func ReadYamlFile(path string, c *Config) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		LogIt(ERROR, "", err, c.Debug)
		return
	}
	LogIt(INFO, path, nil, c.Debug)
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
		LogIt(ERROR, "", err, c.Debug)
		return
	}

	if SkipSigmaRule(&sigmaRule, c) {
		return
	}

	rule := BuildRule(&sigmaRule, url, c)
	c.Wazuh.XmlRules.Rules = append(c.Wazuh.XmlRules.Rules, rule)
}

func WriteWazuhXmlRules(c *Config) {
	// Create an XML encoder that writes to the file
	enc := xml.NewEncoder(&c.Wazuh.WriteRules)
	enc.Indent("", "  ")

	// Encode the rule struct to XML
	if err := enc.Encode(c.Wazuh.XmlRules); err != nil {
		LogIt(ERROR, "", err, c.Debug)
	}
	if _, err := c.Wazuh.WriteRules.WriteString("\n"); err != nil {
		LogIt(ERROR, "", err, c.Debug)
	}
}

func getArgs(args []string, c *Config) bool {
	if !c.Debug {
		if len(args) == 1 {
			return c.Debug
		}
		debug := args[1]
		debugArgs := []string{"-d", "--debug"}
		return slices.Contains(debugArgs, strings.ToLower(debug))
	}
	return c.Debug
}

func main() {
	c := InitConfig()
	c.Debug = getArgs(os.Args, c)

	// Convert rules
	file, err := os.Create(c.Wazuh.RulesFile)
	if err != nil {
		LogIt(ERROR, "", err, c.Debug)
		return
	}
	c.Wazuh.WriteRules = *file
	defer file.Close()

	err = filepath.Walk(c.Sigma.RulesRoot, c.getSigmaRules)
	if err != nil {
		LogIt(ERROR, c.Sigma.RulesRoot, err, c.Debug)
	}

	// build our xml rule file and write it
	c.Wazuh.XmlRules.Name = "sigma,"
	c.Wazuh.XmlRules.Header = xml.Comment("\n\tAuthor: Brian Kellogg\n\tSigma: https://github.com/SigmaHQ/sigma\n\tWazuh: https://wazuh.com\n\tAll Sigma rules licensed under DRL: https://github.com/SigmaHQ/Detection-Rule-License ")
	WriteWazuhXmlRules(c)

	// Convert map to json
	jsonData, err := json.Marshal(c.Ids.SigmaToWazuh)
	if err != nil {
		LogIt(ERROR, "", err, c.Debug)
	}
	// Write JSON data to a file
	err = ioutil.WriteFile(c.Wazuh.RuleIdFile, jsonData, 0644)
	if err != nil {
		LogIt(ERROR, "", err, c.Debug)
	}
}

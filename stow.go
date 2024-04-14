package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Sigma struct {
		BaseUrl             string   `yaml:"BaseUrl"`
		ConvertAll          bool     `yaml:"ConvertAll"`
		ConvertCategories   []string `yaml:"ConvertCategories"`
		ConvertProducts     []string `yaml:"ConvertProducts"`
		ConvertServices     []string `yaml:"ConvertServices"`
		ProcessExperimental bool     `yaml:"ProcessExperimental"`
		RulesRoot           string   `yaml:"RulesRoot"`
		SkipCategories      []string `yaml:"SkipCategories"`
		SkipIds             []string `yaml:"SkipIds"`
		SkipProducts        []string `yaml:"SkipProducts"`
		SkipServices        []string `yaml:"SkipServices"`
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
		IdMaps struct {
			SigmaIdToWazuhGroup        map[string]string `yaml:"SigmaIdToWazuhGroup"`
			SigmaIdToWazuhId           map[string]string `yaml:"SigmaIdToWazuhId"`
			ProductServiceToWazuhGroup map[string]string `yaml:"ProductServiceToWazuhGroup"`
			ProductServiceToWazuhId    map[string]string `yaml:"ProductServiceToWazuhId"`
		} `yaml:"IdMaps"`
		FieldMaps map[string]map[string]string `yaml:"FieldMaps"`
	} `yaml:"Wazuh"`
}

func (c *Config) lookIn(path string, f os.FileInfo, err error) error {
	if !f.IsDir() && strings.HasSuffix(path, ".yml") {
		//fmt.Println("Found YAML file:", path)
		readYamlFile(path, c)
	}
	return nil
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
		Category string `yaml:"category"`
	} `yaml:"logsource"`
	Detection struct {
		FieldLogic interface{} `yaml:"selection"`
		Condition  string      `yaml:"condition"`
	} `yaml:"detection"`
	FalsePositives []string `yaml:"falsepositives"`
	Level          string   `yaml:"level"`
}

type WazuhRule struct {
	XMLName xml.Name `xml:"rule"`
	ID      string   `xml:"id,attr"`
	Level   string   `xml:"level,attr"`
	Info    struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"info"`
	Author           xml.Comment `xml:",comment"`
	SigmaDescription xml.Comment `xml:",comment"`
	Date             xml.Comment `xml:",comment"`
	Modified         xml.Comment `xml:",comment"`
	Status           xml.Comment `xml:",comment"`
	SigmaID          xml.Comment `xml:",comment"`
	Mitre            struct {
		IDs []string `xml:"id"`
	} `xml:"mitre"`
	Description string `xml:"description"`
	Options     string `xml:"options"`
	Group       string `xml:"group"`
	Fields      []struct {
		Name   string `xml:"name,attr"`
		Negate string `xml:"negate,attr"`
		Type   string `xml:"type,attr"`
		Value  string `xml:",chardata"`
	} `xml:"field"`
}

func buildRule(sigma SigmaRule, url string) WazuhRule {
	var rule WazuhRule

	rule.ID = "0"
	rule.Level = "0"
	rule.Description = sigma.Title
	rule.Info.Type = "link"
	rule.Info.Value = url
	rule.Author = xml.Comment(sigma.Author)
	rule.SigmaDescription = xml.Comment(sigma.Description)
	rule.Date = xml.Comment(sigma.Date)
	rule.Modified = xml.Comment(sigma.Modified)
	rule.Status = xml.Comment(sigma.Status)
	rule.SigmaID = xml.Comment(sigma.ID)
	rule.Mitre.IDs = sigma.Tags

	return rule
}

// func addElement(enc *xml.Encoder, elementName, content string) error {
// 	// Start the element
// 	if err := enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: elementName}}); err != nil {
// 		return err
// 	}

// 	// Add the content
// 	if err := enc.EncodeToken(xml.CharData(content)); err != nil {
// 		return err
// 	}

// 	// End the element
// 	if err := enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: elementName}}); err != nil {
// 		return err
// 	}

// 	return nil
// }

func readYamlFile(path string, c *Config) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}
	fmt.Println(path)
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
		fmt.Printf("Error parsing YAML: %v\n", err)
		return
	}

	rule := buildRule(sigmaRule, url)

	// Create an XML encoder that writes to the file
	enc := xml.NewEncoder(&c.Wazuh.WriteRules)
	enc.Indent("", "  ")

	// Encode the rule struct to XML
	if err := enc.Encode(rule); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	if _, err := c.Wazuh.WriteRules.WriteString("\n"); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
}

func main() {
	data, err := ioutil.ReadFile("./config.yaml")
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}
	var c Config
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		fmt.Printf("Error parsing YAML: %v\n", err)
		return
	}
	fmt.Println(c.Wazuh.FieldMaps)

	file, err := os.Create(c.Wazuh.RulesFile)
	if err != nil {
		fmt.Printf("error: %v", err)
		return
	}
	c.Wazuh.WriteRules = *file
	defer file.Close()

	err = filepath.Walk(c.Sigma.RulesRoot, c.lookIn)
	if err != nil {
		fmt.Printf("Error walking the path %v: %v\n", c.Sigma.RulesRoot, err)
	}
}
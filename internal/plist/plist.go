package plist

import (
	"encoding/xml"
	"fmt"
	"strings"
)

type Plist struct {
	XmlTag   string
	DocType  string
	PlistMap map[string]any
}

type PlistArray struct {
	Integer []int    `xml:"integer"`
	String  []string `xml:"string"`
}

func Unmarshal(content string, result *Plist) error {
	doc := xml.NewDecoder(strings.NewReader(content))
	doc.Strict = false

	mainDictFound := false
	var workingKey string
	var nestedDictKey string
	inNestedDict := false
	nestedDict := map[string]any{}

	for {
		token, _ := doc.Token()
		if token == nil {
			break
		}
		switch start := token.(type) {
		case xml.StartElement:
			switch start.Name.Local {
			case "key":
				var key string
				err := doc.DecodeElement(&key, &start)
				if err != nil {
					return err
				}
				if inNestedDict {
					nestedDictKey = key
				} else {
					workingKey = key
				}
			case "string":
				var val string
				err := doc.DecodeElement(&val, &start)
				if err != nil {
					return err
				}
				if inNestedDict {
					nestedDict[nestedDictKey] = val
				} else {
					result.PlistMap[workingKey] = val
				}
			case "integer":
				var i int
				err := doc.DecodeElement(&i, &start)
				if err != nil {
					return err
				}

				if inNestedDict {
					nestedDict[nestedDictKey] = i
				} else {
					result.PlistMap[workingKey] = i
				}
			case "array":
				var arr PlistArray
				err := doc.DecodeElement(&arr, &start)
				if err != nil {
					return err
				}

				if inNestedDict {
					nestedDict[nestedDictKey] = arr
				} else {
					result.PlistMap[workingKey] = arr
				}
			case "true":
				if inNestedDict {
					nestedDict[nestedDictKey] = true
				} else {
					result.PlistMap[workingKey] = true
				}
			case "false":
				if inNestedDict {
					nestedDict[nestedDictKey] = false
				} else {
					result.PlistMap[workingKey] = false
				}
			case "dict":
				if mainDictFound {
					inNestedDict = true
					nestedDict = map[string]any{}
				} else {
					mainDictFound = true
				}
			}
		case xml.EndElement:
			if inNestedDict && start.Name.Local == "dict" {
				inNestedDict = false
				nestedDictKey = ""
				result.PlistMap[workingKey] = nestedDict
			}
		}
	}

	return nil
}

func Marshal(m map[string]any, justDict bool) string {
	plistTemplate := `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
	%s
	</dict>
</plist>`

	plist := ""
	for key, value := range m {
		keyStr := fmt.Sprintf("\t\t<key>%s</key>", key)
		plist = fmt.Sprintf("\t\t%s\n%s", plist, keyStr)
		switch v := value.(type) {
		case map[string]any:
			// nested dict
			value := Marshal(v, true)
			value = strings.ReplaceAll(value, "\n", "\n\t")
			valueStr := fmt.Sprintf("\t\t<dict>\n%s\n\t\t</dict>", value)
			plist = fmt.Sprintf("\t\t%s\n%s", plist, valueStr)
		case bool:
			var valStr string
			if v {
				valStr = "\t\t<true/>"
			} else {
				valStr = "\t\t<false/>"
			}
			plist = fmt.Sprintf("%s\n%s", plist, valStr)
		case PlistArray:
			if len(v.Integer) > 0 {
				s := ""
				for _, i := range v.Integer {
					s = fmt.Sprintf("\t\t\t<integer>%d</integer>\n", i)
				}
				valStr := fmt.Sprintf("\t\t<array>\n\t%s\n\t\t</array>", s)
				plist = fmt.Sprintf("%s\n%s", plist, valStr)
			} else if len(v.String) > 0 {
				s := ""
				for _, str := range v.String {
					s = fmt.Sprintf("\t\t\t<string>%s</string>\n", str)
				}
				valStr := fmt.Sprintf("\t\t<array>\n\t%s\n\t\t</array>", s)
				plist = fmt.Sprintf("%s\n%s", plist, valStr)
			}
		case int:
			s := fmt.Sprintf("\t\t<integer>%d</integer>\n", v)
			plist = fmt.Sprintf("%s\n%s", plist, s)
		case string:
			s := fmt.Sprintf("\t\t<string>%s</string>\n", v)
			plist = fmt.Sprintf("%s\n%s", plist, s)
		}
	}

	if justDict {
		return plist
	}

	return fmt.Sprintf(plistTemplate, plist)
}

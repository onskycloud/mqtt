package mqtt

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/onskycloud/rbac/model"
	proto "github.com/onskycloud/rbac/proto/calling"
)

// TimeZone default time zone
const TimeZone = "Asia/Ho_Chi_Minh"

// FindTimeZone find timezone of a thing
func FindTimeZone(properties []*proto.Property, defaultTimezone string) string {
	if defaultTimezone != "" {
		defaultTimezone = TimeZone
	}
	for _, n := range properties {
		if n.Name == "timezone" && n.Value != "" {
			return n.Value
		}
	}
	return defaultTimezone
}

// ParseTopic parse mqtt topic
func ParseTopic(prefix string, topic string) (string, error) {
	s1 := strings.Split(topic, "/")
	if s1 == nil || len(s1) < 2 {
		return "", errors.New("invalid:topic")
	}
	if s1[0] != prefix {
		return "", errors.New("invalid:prefix")
	}
	return s1[1], nil
}

// FindValue find a value from list property
func FindValue(properties []*proto.Property, name string, defaultValue string) string {
	if properties == nil || len(properties) == 0 {
		return defaultValue
	}
	for _, n := range properties {
		if n.Name == name && n.Value != "" {
			return n.Value
		}
	}

	return defaultValue
}

// FindModeValue detect mode value in security and safety
func FindModeValue(array []*proto.Property, name string) int {
	for _, n := range array {
		if name == n.Name {
			return ConvertStringToInt(n.Value)
		}
	}
	return 0
}

// GetTimeZone get time zone from locale string
func GetTimeZone(locale string) string {
	timezone := "Asia/Ho_Chi_Minh"
	if locale == "" {
		return timezone
	}
	switch locale {
	case "en-US":
		timezone = "America/Mazatlan"
		break
	case "vi-VN":
		break
	default:
		break
	}
	return timezone
}

// IsMn is mn rune
func IsMn(r rune) bool {
	return unicode.Is(unicode.Mn, r) // Mn: nonspacing marks
}

// CheckTemplateType detect resource type depend on template
func CheckTemplateType(name string) model.SecurityType {
	switch name {
	case "CO Detector":
		return model.Co
	case "Smoke Detector":
		return model.Smoke
	case "SOS Button":
		return model.SOS
	case "Temperature-Humidity Sensor":
		return model.TempHumd
	case "Zigbee Door Lock":
		return model.DoorLock
	case "OS Locus":
		return model.OSLocus
	default:
		return model.Motion
	}
}

// ConvertStringToInt convert string to int
func ConvertStringToInt(text string) int {
	value, err := strconv.Atoi(text)
	if err != nil {
		return 0
	}
	return value
}

//GetNotificationType get notification type
func GetNotificationType(securityType model.SecurityType) model.NotificationType {
	switch securityType {
	case model.Co:
		return model.SafetyBreachCO
	case model.Smoke:
		return model.SafetyBreachSmoke
	case model.TempHumd:
		return model.SafetyBreachTempHumd
	case model.SOS:
		return model.SafetyBreachSOS
	case model.DoorLock:
		return model.SecurityBreach
	case model.OSLocus:
		return model.SafetyBreachSOS
	case model.Motion:
		return model.SecurityBreach
	default:
		return model.SecurityBreach
	}
}

// CheckSecurityState detect mode is security or safety
func CheckSecurityState(templateType model.SecurityType) model.Mode {
	switch templateType {
	case model.Co:
		return model.Safety
	case model.Smoke:
		return model.Safety
	case model.SOS:
		return model.Safety
	case model.TempHumd:
		return model.Safety
	case model.OSLocus:
		return model.Basic
	case model.DoorLock:
		return model.Security
	default:
		return model.Security
	}
}

// ConvertMode convert string to mode
func ConvertMode(mode string) model.Mode {
	switch mode {
	case "safe":
		return model.Safety
	case "safety":
		return model.Safety
	case "security":
		return model.Security
	default:
		return model.Security
	}
}

//-------------PREPARE BODY HELPER--------------------

// PrepareResourceLocale prepare text message for any locale
func PrepareResourceLocale(templateType model.NotificationType, key string, locale string, gatewayName string, deviceName string, zoneName string, date string, timestamp string) string {
	switch locale {
	case "en-US":
		switch key {
		case "onsky_security":
			return "OnSky Security & Safety service"
		case "zone":
			return "zone"
		case "gateway_name":
			return gatewayName
		case "zone_name":
			return zoneName
		case "device":
			return "device"
		case "device_name":
			return deviceName
		case "on_date":
			return "on"
		case "date":
			return date
		case "at_time":
			return "at"
		case "time":
			return timestamp
		case "please_check":
			return "Please check"
		case "security_alert":
			switch templateType {
			case model.SafetyBreachCO:
				return "Detects toxic gas CO exceeds exposure limits at"
			case model.SafetyBreachSmoke:
				return "Detecting fire signs at"
			case model.SafetyBreachSOS:
				return "Emergency SOS signals are sent from the area"
			case model.SafetyBreachTempHumd:
				return "Room temperature exceeds the threshold allowed"
			case model.OSLocusSOS:
				return "Emergency signals are sent from your WAVTRAXX device"
			case model.OSLocusTemp:
				return "WAVTRAXX detect a temperature exceeds the threshold allowed"
			default:
				return "Intruder detected in"
			}
		}
		return ""
	default:
		switch key {
		case "onsky_security":
			return "Dich vu an ninh & an toan OnSky"
		case "zone":
			return "khu"
		case "gateway_name":
			return gatewayName
		case "zone_name":
			return zoneName
		case "device":
			return "thiet bi"
		case "device_name":
			return deviceName
		case "on_date":
			return "Vao ngay"
		case "date":
			return date
		case "at_time":
			return "luc"
		case "time":
			return timestamp
		case "please_check":
			return "Vui long kiem tra"
		case "security_alert":
			switch templateType {
			case model.SafetyBreachCO:
				return "Phat hien khi doc CO vuot nguong cho phep tai"
			case model.SafetyBreachSmoke:
				return "Phat hien dau hieu chay no tai"
			case model.SafetyBreachSOS:
				return "Tin hieu khan cap SOS duoc gui di tu khu"
			case model.SafetyBreachTempHumd:
				return "Nhiet do trong phong vuot qua nguong cho phep"
			case model.OSLocusSOS:
				return "Tin hieu khan cap duoc gui di tu thiet bi WAVTRAXX"
			case model.OSLocusTemp:
				return "Thiet bi WAVTRAXX phat hien nhiet do vuot qua nguong cho phep"
			default:
				return "Phat hien dot nhap tai"
			}
		}
		return ""
	}
}

// PrepareBody prepare body of a message
func PrepareBody(templateType model.NotificationType, locale string, gatewayName string, deviceName string, zoneName string, timezone string) string {
	now := time.Now()
	if timezone == "" {
		timezone = GetTimeZone(locale)
	}
	//init the loc
	loc, err := time.LoadLocation(timezone)
	//set timezone,
	if err == nil {
		now = now.In(loc)
	} else {
		log.Println("error loc", err)
	}
	date := strconv.Itoa(now.Day()) + "/" + strconv.Itoa(int(now.Month()))
	timestamp := strconv.Itoa(now.Hour()) + ":" + strconv.Itoa(now.Minute())

	template := "{{onsky_security}}. {{security_alert}} {{zone}} {{gateway_name}}-{{zone_name}}, {{device}} {{device_name}}. {{on_date}} {{date}}, {{at_time}} {{time}}. {{please_check}} ."
	str := strings.Replace(template, "{{onsky_security}}", PrepareResourceLocale(templateType, "onsky_security", locale, gatewayName, deviceName, zoneName, "", ""), -1)
	str = strings.Replace(str, "{{zone}}", PrepareResourceLocale(templateType, "zone", locale, gatewayName, deviceName, zoneName, "", ""), -1)
	str = strings.Replace(str, "{{gateway_name}}", PrepareResourceLocale(templateType, "gateway_name", locale, gatewayName, deviceName, zoneName, "", ""), -1)
	str = strings.Replace(str, "{{zone_name}}", PrepareResourceLocale(templateType, "zone_name", locale, gatewayName, deviceName, zoneName, "", ""), -1)
	str = strings.Replace(str, "{{device}}", PrepareResourceLocale(templateType, "device", locale, gatewayName, deviceName, zoneName, "", ""), -1)
	str = strings.Replace(str, "{{device_name}}", PrepareResourceLocale(templateType, "device_name", locale, gatewayName, deviceName, zoneName, "", ""), -1)
	str = strings.Replace(str, "{{on_date}}", PrepareResourceLocale(templateType, "on_date", locale, gatewayName, deviceName, zoneName, "", ""), -1)
	str = strings.Replace(str, "{{date}}", PrepareResourceLocale(templateType, "date", locale, gatewayName, deviceName, zoneName, date, ""), -1)
	str = strings.Replace(str, "{{at_time}}", PrepareResourceLocale(templateType, "at_time", locale, gatewayName, deviceName, zoneName, "", ""), -1)
	str = strings.Replace(str, "{{time}}", PrepareResourceLocale(templateType, "time", locale, gatewayName, deviceName, zoneName, "", timestamp), -1)
	str = strings.Replace(str, "{{please_check}}", PrepareResourceLocale(templateType, "please_check", locale, gatewayName, deviceName, zoneName, "", ""), -1)
	str = strings.Replace(str, "{{security_alert}}", PrepareResourceLocale(templateType, "security_alert", locale, gatewayName, deviceName, zoneName, "", ""), -1)
	return str
}

// PrepareMedia prepare a media url
func PrepareMedia(templateType model.NotificationType, locale string) string {
	callType := strings.ToLower(strings.Replace(templateType.String(), " ", "-", -1))
	return fmt.Sprintf("?safety=%s&locale=%s", callType, locale)
}

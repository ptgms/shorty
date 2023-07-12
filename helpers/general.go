package helpers

import (
	"encoding/base64"
	"encoding/json"
	"os"
)

// AuthUser is the return value of the verifyToken function
type AuthUser struct {
	Username string
	ID       string
}

// PermittedUsers contains a list of all users permitted to access the site.
type PermittedUsers []struct {
	ID    string `json:"id"`    // discord id / google id / github id
	Power int    `json:"power"` // 0 = admin, 1 = user
}

type Configuration struct {
	PermittedUsers PermittedUsers `json:"permittedusers"`
	Database       struct {
		Host     string `json:"host"`
		Port     string `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		Database string `json:"database"`
	} `json:"database"`
	Webserver struct {
		Domain    string `json:"domain"`
		Host      string `json:"host"`
		Port      string `json:"port"`
		RootServe string `json:"rootserve"`
	} `json:"webserver"`
	OAuth struct {
		Type         string `json:"type"`
		ClientID     string `json:"clientid"`
		ClientSecret string `json:"clientsecret"`
		RedirectURL  string `json:"redirecturl"`
		Secret       string `json:"secret"`
	} `json:"oauth"`
}

type PageTable struct {
	ID            int
	ShortLink     string
	ShortLinkFull string
	Link          string
	Clicks        int
	AddedOn       string
	ExpiresAt     string
}

type PageData struct {
	PageTitle string
	LoginName string
	Links     []PageTable
	Footer    string
}

func IsIDPermitted(id string, permittedUsers PermittedUsers) bool {
	for _, permittedUser := range permittedUsers {
		if permittedUser.ID == id {
			return true
		}
	}
	return false
}

func DoesFileExist(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}

func SaveEmptyConfig() {
	var config Configuration
	config.PermittedUsers = PermittedUsers{
		{
			ID:    "",
			Power: 0,
		},
	}
	config.Database.Host = "localhost"
	config.Database.Port = "5432"
	config.Database.User = ""
	config.Database.Password = ""
	config.Database.Database = ""
	config.Webserver.Domain = ""
	config.Webserver.Host = "localhost"
	config.Webserver.Port = "8081"
	config.Webserver.RootServe = "./index.html"
	config.OAuth.Type = "discord / google / github"
	config.OAuth.ClientID = ""
	config.OAuth.ClientSecret = ""
	config.OAuth.RedirectURL = ""
	config.OAuth.Secret = "Tip: Run pwgen -s -1 30"

	// open file
	file, err := os.Create("config.json")
	HandleError(err, false)
	defer file.Close()

	b, err := json.MarshalIndent(config, "", "    ")
	HandleError(err, false)

	_, err = file.Write(b)
	HandleError(err, false)
}

func LoadConfig() Configuration {
	file, err := os.Open("config.json")
	HandleError(err, false)
	defer file.Close()

	decoder := json.NewDecoder(file)
	config := Configuration{}
	err = decoder.Decode(&config)
	HandleError(err, false)

	return config
}

func Base64Decode(base64S string) string {
	decoded, err := base64.StdEncoding.DecodeString(base64S)
	HandleError(err, false)
	return string(decoded)
}

func HandleError(err error, fatal bool) {
	if err != nil {
		if fatal {
			panic(err)
		} else {
			println(err.Error())
		}
	}
}

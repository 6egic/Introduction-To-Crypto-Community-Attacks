package main

import (
	"golang.org/x/crypto/pbkdf2"

	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"fmt"
	"log"
	"os/exec"
	"os/user"
	"strings"

	//register the sqlite3 driver as a database driver !importing any other functions.
	_ "github.com/mattn/go-sqlite3"
)

//Inspiration
//http://n8henrie.com/2013/11/use-chromes-cookies-for-easier-downloading-with-python-requests/

var (
	salt       = "saltysalt"
	iv         = "                " //16
	length     = 16
	password   = ""
	iterations = 1003
)

//Cookie contains the components for a cookie.
type Cookie struct {
	Domain         string
	Key            string
	Value          string
	EncryptedValue []byte
}

//This function retrieves the decrypted value of a Chrome cookie.
func (c *Cookie) getValue() string {
	if c.Value > "" {
		return c.Value
	}

	if len(c.EncryptedValue) > 0 {
		encryptedValue := c.EncryptedValue[3:]
		return decryptValue(encryptedValue)
	}

	return ""
}

//This function decrypts the unencrypted value of a Chrome cookie.
func decryptValue(encryptedValue []byte) string {
	//derive a key based on pbkdf2 methodology
	key := pbkdf2.Key([]byte(password), []byte(salt), iterations, length, sha1.New)
	//create new cipher block based on previously derived key
	b, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	decrypted := make([]byte, len(encryptedValue))
	//@cbc contains a block cipher which decrypts in cipher block chaining mode
	bc := cipher.NewCBCDecrypter(b, []byte(iv))
	//decrypts a number of blocks
	bc.CryptBlocks(decrypted, encryptedValue)

	//AES in cbc mode has a fixed encryption block size, we remove added padding during decryption
	plainText, err := removeAESPadding(decrypted)
	if err != nil {
		fmt.Println("[!] an error occured during decryption:", err)
		return ""
	}
	return string(plainText)
}

//This function removes any addition of padding
//In the padding scheme the last <padding length> bytes
//have a value equal to the padding length, always in (1,16]
func removeAESPadding(data []byte) ([]byte, error) {
	if len(data)%length != 0 {
		return nil, fmt.Errorf("[!] removeAESPadding() returned with code %d", length)
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen > 16 {
		return nil, fmt.Errorf("[!] removeAESPadding() returned with code %d", paddingLen)
	}
	return data[:len(data)-paddingLen], nil
}

//This function retrieves the password used to encrypt the cookies by chrome from the OSX Keychain.
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

//This function retrieves the cookies of concern from the SQLite File which contains the cookies.
func getCookies(domain string) (cookies []Cookie) {
	usr, _ := user.Current()
	//this is the path to the cookie file.
	cookiesFile := fmt.Sprintf("%s/Library/Application Support/Google/Chrome/Default/Cookies", usr.HomeDir)

	db, err := sql.Open("sqlite3", cookiesFile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	//Constructed query which retrieves the data that we want from the SQLite File which contains the cookies.
	rows, err := db.Query("SELECT name, value, host_key, encrypted_value FROM cookies WHERE host_key like ?", fmt.Sprintf("%%%s%%", domain))
	if err != nil {
		log.Fatal(err)
	}
	//Cookies are stored as rows in the SQLite file which contains the cookies.
	defer rows.Close()
	for rows.Next() {
		var name, value, hostKey string
		var encryptedValue []byte
		rows.Scan(&name, &value, &hostKey, &encryptedValue)
		cookies = append(cookies, Cookie{hostKey, name, value, encryptedValue})
	}
	return
}

func main() {
	target := "Poloniex.com"
	password = getPassword()

	//Below controls prints any stored cookies related to the target to the Terminal.
	for _, cookie := range getCookies(target) {
		fmt.Printf("%s/%s: %s\n", cookie.Domain, cookie.Key, cookie.getValue())
	}
}


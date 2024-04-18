package tests

import (
	"fmt"
	"log"

	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
)

func RunSeleniumTest() {
	// Set up Selenium WebDriver capabilities for Chrome
	caps := selenium.Capabilities{
		"browserName": "chrome",
	}

	// Set ChromeDriver path (replace "/path/to/chromedriver" with your actual path)
	chromeDriverPath := "/path/to/chromedriver"

	// Create ChromeOptions with the ChromeDriver path
	chromeCaps := chrome.Capabilities{
		Path: chromeDriverPath,
	}
	caps.AddChrome(chromeCaps)

	// Initialize Selenium WebDriver
	wd, err := selenium.NewRemote(selenium.Capabilities(caps), fmt.Sprintf("http://localhost:4444/wd/hub"))
	if err != nil {
		log.Fatalf("Failed to open session: %v", err)
	}
	defer wd.Quit()

	// Navigate to the registration page
	if err := wd.Get("http://localhost:8080/register-users"); err != nil {
		log.Fatalf("Failed to load page: %v", err)
	}

	// Find and fill in the email input field
	emailField, err := wd.FindElement(selenium.ByID, "email")
	if err != nil {
		log.Fatalf("Failed to find email field: %v", err)
	}
	if err := emailField.SendKeys("test@example.com"); err != nil {
		log.Fatalf("Failed to enter email: %v", err)
	}

	// Find and fill in the password input field
	passwordField, err := wd.FindElement(selenium.ByID, "password")
	if err != nil {
		log.Fatalf("Failed to find password field: %v", err)
	}
	if err := passwordField.SendKeys("testpassword"); err != nil {
		log.Fatalf("Failed to enter password: %v", err)
	}

	// Submit the registration form
	submitButton, err := wd.FindElement(selenium.ByID, "submit-button")
	if err != nil {
		log.Fatalf("Failed to find submit button: %v", err)
	}
	if err := submitButton.Click(); err != nil {
		log.Fatalf("Failed to click submit button: %v", err)
	}

	fmt.Println("Registration form submitted successfully!")
}

from selenium import webdriver
from selenium.webdriver.common.by import By

driver = webdriver.Chrome()

driver.get("https://easyclocking.net/")

driver.implicitly_wait(15)

companyCode = driver.find_element(By.NAME, "CompanyCode")
userName = driver.find_element(By.NAME, "UserName")
passWord = driver.find_element(By.NAME, "Password")


companyCode.send_keys("companyCode")
userName.send_keys("user")
passWord.send_keys("password")

driver.implicitly_wait(15)


signInButton = driver.find_element_by_xpath("//input[@type='submit']")
signInButton.click()

driver.implicitly_wait(15)

clockInButton = driver.find_element_by_xpath("//input[@id='clocktime']")
clockInButton.click()

driver.implicitly_wait(15)

options = webdriver.ChromeOptions()
options.add_experimental_option("detach", True)


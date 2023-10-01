from selenium import webdriver
from selenium.webdriver.common.by import By
import time
from tqdm import trange

PATH = './PicoCTF/Web/Java Script Kiddie/chromedriver.exe'
driver = webdriver.Chrome()
driver.get('https://jupiter.challenges.picoctf.org/problem/17205/?#')


img = driver.find_element(By.ID, "Area")

ct = '51081803ghi63640'
pt_guess = []
for i in range(2, 5):
    for j in range(3, 7):
        for k in range(2, 5):
            pt_guess.append(ct.replace('g', hex(i)[2:]).replace('h', hex(j)[2:]).replace('i', hex(k)[2:]))
            print(pt_guess[-1])

for i in trange(len(pt_guess)):
    element = driver.find_element(By.ID, 'user_in')
    click = driver.find_element(By.XPATH, "/html/body/center/form/input[2]")
    element.send_keys(pt_guess[i])
    click.click()
    time.sleep(0.01)
    driver.refresh()
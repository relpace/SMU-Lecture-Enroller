import json
import time
from datetime import datetime
from io import BytesIO
import pytz
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PIL import Image
from bs4 import BeautifulSoup

captcha_url = "https://zhjw.smu.edu.cn/yzm?d="
login_url = "https://zhjw.smu.edu.cn/new/login"
headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "keep-alive",
    "Host": "zhjw.smu.edu.cn",
    "Referer": "https://zhjw.smu.edu.cn/",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}


def encrypt_password(password, verifycode):
    key = (verifycode * 4).encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    return encrypted.hex()


def get_captcha(session):
    captcha_response = session.get(captcha_url + str(int(time.time() * 1000)), headers=headers)
    img = Image.open(BytesIO(captcha_response.content))
    img.show()
    captcha = input("请输入验证码: ")
    return captcha


def login(account, password, captcha, session):
    encrypted_password = encrypt_password(password, captcha)
    data = {
        "account": account,
        "pwd": encrypted_password,
        "verifycode": captcha
    }
    response = session.post(login_url, data=data, headers=headers)
    if response.status_code == 200 and "成功" in response.text:
        print("登录成功")
        print(response.url)
        calibration(response)
        get_course_category(session)
    else:
        print("登录失败，原因：", response.text)


def calibration(response):
    servertime_str = response.headers['Date']
    servertime = datetime.strptime(servertime_str, '%a, %d %b %Y %H:%M:%S GMT')
    servertime = servertime.replace(tzinfo=pytz.timezone('GMT'))
    chinatime = servertime.astimezone(pytz.timezone('Asia/Shanghai'))
    localtime = datetime.now(pytz.timezone('Asia/Shanghai'))
    global time_diff
    time_diff = chinatime - localtime
    print(f'时间差值：{time_diff}')
    time_diff_totalsec = time_diff.total_seconds()
    print(time_diff_totalsec)
    print(f'currtime:{localtime}')


def get_course_category(session):
    session.get("https://zhjw.smu.edu.cn/new/welcome.page", headers=headers)
    url = "https://zhjw.smu.edu.cn/new/xsxk/"
    response = session.get(url, headers=headers)
    soup = BeautifulSoup(response.content, 'lxml')
    courses = soup.find_all('li', {'style': True})
    print("选课类型：")
    coursedict = {}
    for idx, course in enumerate(courses, start=1):
        course_name = course.find('p').text.strip()
        course_link = course['data-href']
        coursedict[idx] = course_link
        print(f"{idx}. {course_name}")
    get_course_list(session, "https://zhjw.smu.edu.cn" + coursedict[int((input("请填写序号")))])


def get_course_list(session, coursecateurl):
    geturl = coursecateurl + '/kxkc'
    payload = {
        'page': 1,
        'rows': 20,
        'sort': 'kcrwdm',
        'order': 'asc'
    }
    response = session.post(geturl, headers=headers, data=payload)
    total = json.loads(response.text)['total']
    courses = json.loads(response.text)['rows']
    while len(courses) < total:
        payload['page'] += 1
        response = session.post(geturl, headers=headers, data=payload)
        temp = json.loads(response.text)['rows']
        for course in temp:
            courses.append(course)
    for i in range(len(courses)):
        print(f"{i + 1}. {courses[i]['kcmc']} {courses[i]['teaxm']}")
    order1 = int(input('请输入第一志愿课程对应序号'))
    order2 = int(input('请输入第二志愿课程对应序号'))
    selection_time_str = input('请输入抢课时间。格式为HH:MM:SS 例：13:00:00；08:08:00，注意是英文冒号')
    selection_time = datetime.strptime(selection_time_str, '%H:%M:%S').time()
    currdate = datetime.now().date()
    selection_time = datetime.combine(currdate, selection_time)
    order = order1
    flag = False
    while True:
        now = datetime.now() + time_diff
        if now >= selection_time:
            for i in range(20):
                resp = order_course(session, courses[order - 1]['kcrwdm'], courses[order - 1]['kcmc'], coursecateurl)
                if json.loads(resp.text)['code'] == 0 or json.loads(resp.text)['message'] == '您已经选了该门课程':
                    print('选课成功')
                    break
                elif json.loads(resp.text)['code'] == -1 and not flag:
                    order = order2
                    flag = True
                elif json.loads(resp.text)['code'] == -1 and flag:
                    print('什么都没抢到')
                    break
                time.sleep(0.5)
            break
        time.sleep(0.01)


def order_course(session, kcrwdm, kcmc, url):
    url = url + '/add'
    payload = {
        'kcrwdm': kcrwdm,
        'kcmc': kcmc,
        'hlct': 0
    }
    response = session.post(url, headers=headers, data=payload)
    print(response.text)
    return response


def main():
    account = input('请输入账号')
    password = input('请输入密码')
    session = requests.Session()
    captcha = get_captcha(session)
    login(account, password, captcha, session)


if __name__ == "__main__":
    main()

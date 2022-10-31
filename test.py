import requests
from os.path import dirname, realpath

requests.packages.urllib3.disable_warnings()

test_dir = dirname(realpath(__file__))

# http 301
r = requests.get('http://127.0.0.1/index.html', allow_redirects=False)
assert(r.status_code == 301 and r.headers['Location'] == 'https://127.0.0.1/index.html')

# https 200 OK
r = requests.get('https://127.0.0.1/index.html', verify=False)
assert(r.status_code == 200 and open(test_dir + '/index.html', 'rb').read() == r.content)

# http 200 OK
r = requests.get('http://127.0.0.1/index.html', verify=False)
assert(r.status_code == 200 and open(test_dir + '/index.html', 'rb').read() == r.content)

# http 404
r = requests.get('http://127.0.0.1/notfound.html', verify=False)
assert(r.status_code == 404)

# file in directory
r = requests.get('http://127.0.0.1/dir/index.html', verify=False)
assert(r.status_code == 200 and open(test_dir + '/dir/index.html', 'rb').read() == r.content)

# http 206
headers = { 'Range': 'bytes=100-200' }
r = requests.get('http://127.0.0.1/index.html', headers=headers, verify=False)
# print(open(test_dir + '/index.html', 'rb').read()[100:201])
# print(r.content)
assert(r.status_code == 206 and open(test_dir + '/index.html', 'rb').read()[100:201] == r.content)

# http 206
headers = { 'Range': 'bytes=100-' }
r = requests.get('http://127.0.0.1/index.html', headers=headers, verify=False)
# print(open(test_dir + '/index.html', 'rb').read()[100:200])
# print(r.content[:100])
assert(r.status_code == 206 and open(test_dir + '/index.html', 'rb').read()[100:] == r.content)

# http video
headers = { 'Range': 'bytes=0-' }
r = requests.get('http://127.0.0.1/video.mp4', headers=headers, verify=False)
# print(open(test_dir + '/video.mp4', 'rb').read()[-100:])
# print(r.content[-100:])
assert(r.status_code == 200 and open(test_dir + '/video.mp4', 'rb').read()[0:] == r.content)

# TO DO:https video
# r = requests.get('https://127.0.0.1/video.mp4', verify=False)
# assert(r.status_code == 200 and open(test_dir + '/video.mp4', 'rb').read() == r.content)

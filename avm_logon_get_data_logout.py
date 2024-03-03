#!/usr/bin/env python3

import sys
import hashlib
import time
from urllib import request, parse
import xml.etree.ElementTree as ET

class LoginState:
	def __init__(self, challenge: str, blocktime: int):
		self.challenge = challenge
		self.blocktime = blocktime

def get_sid(box_url: str, username: str, password: str) -> str:
	""" Get a sid by solving the PBKDF2 challenge-response process. """
	try:
		state = get_login_state(box_url)
	except Exception as ex:
		raise Exception("failed to get challenge") from ex
	challenge_response = calculate_pbkdf2_response(state.challenge, password)

	if state.blocktime > 0:
		print(f"Waiting for {state.blocktime} seconds...")
		time.sleep(state.blocktime)
	try:
		sid = send_response(box_url, username, challenge_response)
	except Exception as ex:
		raise Exception("failed to login") from ex
	if sid == "0000000000000000":
		raise Exception("wrong username or password")
	return sid

def get_login_state(box_url: str) -> LoginState:
	http_response = request.urlopen(box_url + "/login_sid.lua?version=2")
	xml = ET.fromstring(http_response.read())
	challenge = xml.find("Challenge").text
	blocktime = int(xml.find("BlockTime").text)
	return LoginState(challenge, blocktime)

def calculate_pbkdf2_response(challenge: str, password: str) -> str:
	""" Calculate the response for a given challenge via PBKDF2 """
	challenge_parts = challenge.split("$")
	# Extract all necessary values encoded into the challenge
	iter1 = int(challenge_parts[1])
	salt1 = bytes.fromhex(challenge_parts[2])
	iter2 = int(challenge_parts[3])
	salt2 = bytes.fromhex(challenge_parts[4])
	# Hash twice, once with static salt...
	hash1 = hashlib.pbkdf2_hmac("sha256", password.encode(), salt1, iter1)
	# Once with dynamic salt.
	hash2 = hashlib.pbkdf2_hmac("sha256", hash1, salt2, iter2)
	return f"{challenge_parts[4]}${hash2.hex()}"

def send_response(box_url: str, username: str, challenge_response: str) -> str:
	http_response = request.urlopen(box_url + "/login_sid.lua?version=2&" + parse.urlencode({"username": username, "response": challenge_response}))
	xml = ET.fromstring(http_response.read())
	return xml.find("SID").text

def main():
	if len(sys.argv) < 4:
		print(f"Usage: {sys.argv[0]} http://fritz.box user pass")
		exit(1)
	url = sys.argv[1]
	username = sys.argv[2]
	password = sys.argv[3]

	sid = get_sid(url, username, password)
	http_response = request.urlopen(url + "/webservices/homeautoswitch.lua?" + parse.urlencode({"switchcmd": "getdevicelistinfos", "sid": sid}))
	xml = ET.fromstring(http_response.read())
	print(float(xml.find("device[@productname='FRITZ!DECT 440']/temperature/celsius").text)/10)
	print(xml.find("device[@productname='FRITZ!DECT 440']/humidity/rel_humidity").text)
	http_response = request.urlopen(url + "/login_sid.lua?version=2&" + parse.urlencode({"logout": "", "sid": sid}))

if __name__ == "__main__":
	main()

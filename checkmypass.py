import requests
import hashlib
import sys


def request_api_data(query_char):
	# Function use to fetch API response
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error Fetching : {res.status_code}, check the API and try again.')
	return res


def get_leaked_passwords_cnt(hashes, hash_to_check):
	# Function to get the count of number to times password has been hacked
	hashes = (line.split(':') for line in hashes.text.splitlines())
	# print(hashes)
	for h, count in hashes:
		# print(h, count)
		if h == hash_to_check:
			return count
	return 0


def pwned_api_check(password):
	#Check if the password is presnt in API Response
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5_char)
	# print(response)
	return get_leaked_passwords_cnt(response, tail)


def main(args):
	# Function used for printing
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times... you should probably change your password !')
		else:
			print(f'{password} was NOT found. Carry ON !!!')
	return 'done!'


if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
class Test():
	def __init__(self, email='test@nisra.net'):
		self.info = 'test'
		self.email = email

class Secret():
	flag = open("./NISRA-Enlightened-2023/flag.txt", "r").read().strip()


if __name__ == '__main__':
	email = input('Your email: ')

	if email:
		test = Test(email)
	else:
		test = Test()

	msg = ('this is for {test.info}, please contact ' + email + '.').format(test=test)

	print(msg)
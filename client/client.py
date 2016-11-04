import socket
import urlparse
import sys
import threading

CRLF = '\r\n'

def get(url, port):
	host = urlparse.urlparse(url).netloc

	host_header = 'Host: ' + host + CRLF

	request_line = 'GET ' + url + ' HTTP/1.0' + CRLF
	headers = host_header
	request = request_line + headers + CRLF

	s = socket.socket()
	s.connect((socket.gethostbyname(host), port))

	s.send(request)

	message = ''
	buffer = None
	buffer_length = 4096

	while buffer != '':
		buffer = s.recv(buffer_length)
		message += buffer

	print('recieved: ' + url)
	
	name = url.split('/')[-1]
	fp = open(name, 'w+')
	fp.write(message)
	fp.close()

def main():
	fp = open('pages', 'r')
	links = fp.read().split('\n')[:-1]
	fp.close()
	t = []
	x = None
	for _ in range(2):
#		print(links)
		for link in links:
			print('requesting: ' + link)
			x = threading.Thread(target=get, args=(link, int(sys.argv[1])))
			x.start()
			t.append(x)
			
			
	for i in t:
		i.join()

if __name__ == '__main__':
	main()

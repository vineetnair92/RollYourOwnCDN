# HTTP Server: Responds to GET requests by fetching from the origin server
# if it is not found in the cache.

# imports
import socket
import urlparse
import os
import sys
import threading
import Queue
import subprocess

# imports for testing
import urllib2

# Constants
ORIGIN_PORT = 8080
CRLF = '\r\n'
CACHE_LIMIT = 10 * (2**20)

DNS_PORT_SEND = 50005
DNS_PORT_RECV = 50004
DNS_HOST = 'cs5700cdnproject.ccs.neu.edu'


class cache():
	# static members
	block_delimiter = chr(0x07)
	key_delimiter = chr(0x13)


	# cache: Integer, String String -> cache
	# Returns: a cache of the given capacity(in bytes) initialized
	# with the contents of the given filename.
	def __init__(self, capacity, origin_name, file_name):
		self.capacity = capacity
		self.origin_name = origin_name
		self.file_name = file_name
		self.size = 0
		# LRU: hottest entry at tail
		self.accessed = []
		self.mappings = self.__load_from_persistence__(self.file_name)

		


	def __load_from_persistence__(self, file_name):
		contents = None
		if os.path.isfile(file_name):
			fp = open(file_name, 'r')
			contents = fp.read()
			fp.close()
		else:
			fp = open(file_name, 'w+')
			fp.write(cache.block_delimiter)
			fp.close()
			contents = cache.block_delimiter
		return self.__generate_map__(contents)

	def __generate_map__(self, contents):
		mappings = {}
		if contents == None:
			return mappings
		contents = contents.split(cache.block_delimiter)
		for block in contents:
			if block != '':
				if cache.key_delimiter in block:
					key, value = block.split(cache.key_delimiter)
					mappings[key] = value
					self.accessed.append(key)
					self.size += sys.getsizeof(value)
		return mappings

#	def contains(self, key):
#		return key in self.mappings

	def get(self, key):
		if key in self.mappings:
			print('From cache!: ' + key)
			self.accessed.remove(key)
			self.accessed.append(key)
			return self.mappings[key]
		print('From origin!: ' + key)
		contents = self.__fetch_from_origin__(key)
		self.__add__(key, contents)
		return self.mappings[key]

	def __fetch_from_origin__(self, path):
		'''
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((socket.gethostbyname(origin_name), origin_port))

		host = origin_name
		

		req_line = 'GET ' + url + ' HTTP/1.0' + CRLF
		headers = 'Host: ' + host + CRLF
		request = req_line + headers + CRLF

		s.send
		'''
		url = urlparse.urlunparse(('http', self.origin_name, path, '', '', ''))
		#print('Trying to get from origin: ' + url)
		return urllib2.urlopen(url).read()

	def __add__(self, key, value):
		if sys.getsizeof(value) > self.capacity:
			#print('Size greater than cache capacity. Exiting')
			sys.exit(1)
		self.__check_and_evict__(sys.getsizeof(value))

		self.accessed.append(key)
		self.mappings[key] = value
		self.size += sys.getsizeof(value)

		self.sync_persistence()

	def __check_and_evict__(self, size):
		#print('self.capacity: ' + str(self.capacity))
		#print('entry size: ' + str(size))
		if self.size + size > self.capacity:
			#print('Entering')
			i = 0
			total_size = 0
			while total_size <= size:
				total_size += sys.getsizeof(self.mappings[self.accessed[i]])
				i += 1
			j = 0
			for j in range(i):
				self.__evict__(self.accessed[j])
			self.accessed = self.accessed[j:]

	def __evict__(self, key):
		#print('Evicting: ' + key)
		self.size -= sys.getsizeof(self.mappings.pop(key))

	def sync_persistence(self):
		contents = ''
		for key,value in self.mappings.iteritems():
			contents += key + cache.key_delimiter + value + cache.block_delimiter
		fp = open(self.file_name, 'w+')
		fp.write(contents)
		fp.close()



def path_from_request(request):
	request_line = request.split(CRLF)[0]
	tokens = request_line.split()

	if tokens[0] == 'GET':
#		netloc = urlparse.urlparse(tokens[1]).netloc
#		return tokens[1].split(netloc)[1]
		path = urlparse.urlparse(tokens[1]).path
		if path == '':
			return '/'
		return path
	return None

# find_loacal_ip : Void -> String
# Returns: The IP address of the device currently active in the local machine.
def find_local_ip():
	s = socket.socket()
	host = socket.gethostbyname('www.ccs.neu.edu')
	s.connect((host, 80))
	ip = s.getsockname()[0]
	s.close()
	return ip

def service(conn, addr):
	print('Connected to ' + str(addr))
	request = conn.recv(2048)
	path = path_from_request(request)

	if path != None:
		conn.send(web_cache.get(path))
	else:
		#print('path is none!')
		conn.send('')
	#print('cache size: ' + str(web_cache.size))
	conn.close()


# server: Integer, String -> Void
# Effect: Listens for GET requests on the given port number
# indefintely.
def server(port, origin_name):
	# store a mapping file and the mapped files. keys will be paths with '/' replaced
	# by '-'.
	# or store in one big file. bet that's more efficient.
	cache_size = 55000
	web_cache = cache(CACHE_LIMIT, origin_name + ':' + str(ORIGIN_PORT), 'my_cache')

	host = 'localhost' #find_local_ip()
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((socket.gethostbyname(host), port))
	s.listen(1)

	while True:
		#print('Waiting for connection:')
		conn, addr = s.accept()
		t = threading.Thread(target=service, args=(conn, addr))
		t.start()
		

def active_measurements():
	pipe = Queue.Queue()
	
	t1 = threading.Thread(target=get_new_clients, args=(pipe,))
	t2 = threading.Thread(target=send_measurements, args=(pipe,))

	t1.start()
	t2.start()

#data format: ' token1 token2 tokenn '
def get_new_clients(pipe):
	connected = False
	new_clients = ''
	data = None
	while True:
		if not connected:
			dns_socket_recv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			dns_socket_recv = dns_socket.connect((socket.gethostbyname(DNS_HOST), DNS_PORT_RECV))
			connected = True
		try:
			data = dns_socket_recv.recv(1024)
		except socket.error as se:
			errnum = se.args[0]
			if errnum == errno.EPIPE:
				connected = False
		new_clients += data
		if (new_clients != '') and (not pipe.full()):
			pipe.put(new_clients)
			new_clients = ''
		if data == '':
			connected = False
	print('get_new_clients closed.')


def send_measurements(pipe, sock):
	connected = False
	clients = set()
	new_clients = ''
	results = ' '
	while True:
		if not connected:
			dns_socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			dns_socket_send = dns_socket.connect((socket.gethostbyname(DNS_HOST), DNS_PORT_SEND))
			connected = True
		while not pipe.empty():
			new_clients += pipe.get()
		if new_clients != '':
			new_clients = new_clients.split()
			for ip in new_clients:
				clients.add(ip)
			new_clients = ''
		results = scamper(list(clients))
		try:
			dns_socket.send(results)
		except socket.error as e:
			connected = False


def execute_command(command):
	#import subprocess
	return subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)


def scamper(ip_list):
	comm = 'scamper -c "ping -c 1" -p 1 -i ' + ' '.join(ip_list)
	results = execute_command(comm)
	return data_from_results(results)

def data_from_results(results):
	results = results.split('\n')
	data = ''
	length = len(results)
	i = 0
	while i < length: 
		if results[i].startswith('--- '):
			data += results[i].split()[1] + ' ' + results[i+2].split(' = ')[1].split('/')[0] + '\n'
			i += 3
		else:
			i += 1
	return data

# main: Void -> Void
# Effect: Starting point of program execution.
def main():
	number_of_args = 4
	argv_1 = '-p'
	argv_3 = '-o'

	if len(sys.argv) != number_of_args + 1:
		print('Bad number of arguments. Exiting.')
		sys.exit(1)
	else:
		if (sys.argv[1] != argv_1) or (sys.argv[3] != argv_3):
			print('Arguments do not follow format. Exiting.')
			sys.exit(1)
		elif not sys.argv[2].isdigit():
			print('Invalid port number. Exiting.')
			sys.exit(1)

		t1 = threading.Thread(target=server, args=(int(sys.argv[2]), sys.argv[4]))
#		t2 = threading.Thread(target=active_measurements)
		
		t1.start()
#		t2.start()

if __name__ == '__main__':
	main()
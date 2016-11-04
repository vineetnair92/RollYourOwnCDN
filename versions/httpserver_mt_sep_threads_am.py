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
import time
import errno

# imports for testing
import urllib2

# Constants
ORIGIN_PORT = 8080
CRLF = '\r\n'
CACHE_LIMIT = 10 * (2**20)

DNS_PORT_SEND = 51004
DNS_PORT_RECV = 51003
#DNS_HOST = '129.10.117.186'
DNS_HOST = socket.gethostbyname('cs5700cdnproject.ccs.neu.edu')

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
					self.size += len(value)
		return mappings

#	def contains(self, key):
#		return key in self.mappings

	def get(self, key):
		if key in self.mappings:
			print('From cache!: ' + key)
			self.accessed.remove(key)
			self.accessed.append(key)
			return self.mappings[key]
		return None
		

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
		if key not in self.mappings:
			if len(value) > self.capacity:
				print('Size greater than cache capacity. Exiting')
				sys.exit(1)
			self.__check_and_evict__(len(value))

			self.accessed.append(key)
			self.mappings[key] = value
			self.size += len(value)

#			self.sync_persistence()

	def __check_and_evict__(self, size):
		#print('self.capacity: ' + str(self.capacity))
		#print('entry size: ' + str(size))
		if self.size + size > self.capacity:
			#print('Entering')
			i = 0
			total_size = 0
			while total_size <= size:
				total_size += len(self.mappings[self.accessed[i]])
				i += 1
			j = 0
			for j in range(i):
				self.__evict__(self.accessed[j])
			self.accessed = self.accessed[j:]

	def __evict__(self, key):
		print('Evicting: ' + key)
		self.size -= len(self.mappings.pop(key))

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
	contents = None

	global web_cache, cache_lock

	if path != None:
		with cache_lock:
#			print('lock acquired: ' + path)
			contents = web_cache.get(path)
#		print('lock released: ' + path)
		if contents != None:
			conn.send(contents)
			conn.close()
		else:
			print('From origin!: ' + path)
			contents = web_cache.__fetch_from_origin__(path)
			conn.send(contents)
			conn.close()
			with cache_lock:
#				print('lock acquiredadd: ' + path)
				web_cache.__add__(path, contents)
#			print('lock releasedadd: ' + path)
	else:
		#print('path is none!')
		conn.send('')
		conn.close()
	#print('cache size: ' + str(web_cache.size))
	

def write_to_persistence(frequency):
	global web_cache, cache_lock
	while True:
		time.sleep(frequency)
		with cache_lock:
			web_cache.sync_persistence()
#			print('synced')


# server: Integer, String -> Void
# Effect: Listens for GET requests on the given port number
# indefintely.
def server(port, origin_name):
	# store a mapping file and the mapped files. keys will be paths with '/' replaced
	# by '-'.
	# or store in one big file. bet that's more efficient.
#	cache_size = 45000

	global web_cache, cache_lock
	web_cache = cache(CACHE_LIMIT, origin_name + ':' + str(ORIGIN_PORT), 'my_cache')
	cache_lock = threading.Lock()

	persistence_write_frequency = 5
	t = threading.Thread(target=write_to_persistence, args=(persistence_write_frequency,))
	t.start()

#	host = 'localhost'
	host = find_local_ip()
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((socket.gethostbyname(host), port))
	s.listen(socket.SOMAXCONN)

	while True:
		#print('Waiting for connection:')
		conn, addr = s.accept()
		t = threading.Thread(target=service, args=(conn, addr))
		t.start()
		

def active_measurements():
	pipe = Queue.Queue()
	
#	global clients, clients_lock
#	clients = set()
#	clients_lock = threading.Lock()

	t1 = threading.Thread(target=get_new_clients, args=(pipe,))
#	t2 = threading.Thread(target=send_measurements, args=(pipe,))

	t1.start()
#	t2.start()


#data format: ' token1 token2 tokenn '
def get_new_clients(pipe):
	connected = False
	new = ''
	data = None
	dns_socket_recv = None
	buff_size = 65535
	clients = set()
#	global clients, clients_lock

	while True:
		if not connected:
			dns_socket_recv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			dns_socket_recv.connect((DNS_HOST, DNS_PORT_RECV))
			dns_socket_recv.setblocking(0)
			connected = True
		try:
			data = dns_socket_recv.recv(buff_size)
			new = data
#			print('Recieved from DNS: ' + data)
		except socket.error as se:
			errnum = se.args[0]
			if errnum == errno.EPIPE:
				connected = False
#		print('this:' + str(new))

		if (new != '') and (not pipe.full()):
			print(new)
			time.sleep(3)
			new = filter(lambda x: x!='', new.split('$'))

			for ip in new:
				if ip not in clients:
					print('new ip: ' + ip)
				clients.add(ip)

#			if pipe.empty():
#				pipe.put(clients)
#			new = ''

#			print(list(pipe.queue))
#		if data == '':
#			connected = False


def send_measurements(pipe):
	fp = open('ips', 'w+')
	fp.write('\n')
	fp.close()


	connected = False
	new = ''
	results = ' '
	dns_socket_send = None

#	global clients, clients_lock
	
	while True:
		if not connected:
			dns_socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			dns_socket_send.connect((DNS_HOST, DNS_PORT_SEND))
			connected = True
			print('send_measurements: connected')

#		with clients_lock:
		'''
		while not pipe.empty():
			new = list(pipe.get())
			print('not empty' + str(new))
		'''

#		print('detect:' + str(new))
		if len(new) > 0:
			print('in')
			results = scamper(list(new))
		try:
			dns_socket_send.send(results)
		except socket.error as e:
			connected = False
		if len(new) > 0:
			fp = open('ips', 'w+')
			fp.write(str(results) + '\n')
			fp.close()
			print('Scamper results:\n' + str(results))
		break



def execute_command(command):
	#import subprocess
	return subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)


def scamper(ip_list):
	comm = '/usr/local/bin/scamper -c "ping -c 1" -p 1 -i ' + ' '.join(ip_list)
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

		port = int(sys.argv[2])
		global DNS_PORT_SEND, DNS_PORT_RECV


		if port > 40000:
			if port > 50000:
				if port > 60000:
					if port > 2**16:
						pass
					else:
						#60k - 2**16
						DNS_PORT_SEND = port - 15328
						DNS_PORT_RECV = port - 15329
				else:
					#50k - 60k
					DNS_PORT_SEND = port - 10528
					DNS_PORT_RECV = port - 10529

			else:
				#40k-50k
				DNS_PORT_SEND = port + 15329
				DNS_PORT_RECV = port + 15328
		else:
			#< 40k
			pass

#		print('dps:' + str(DNS_PORT_SEND))
		print('1:' + str(DNS_PORT_SEND))
		print('2:' + str(DNS_PORT_RECV))


		t1 = threading.Thread(target=server, args=(port, sys.argv[4]))
		t2 = threading.Thread(target=active_measurements)
		
		t1.start()
		t2.start()

if __name__ == '__main__':
	main()
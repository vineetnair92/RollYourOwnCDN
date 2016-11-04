import urlparse
import struct
import socket
import pprint 
import sys
import threading
import Queue
import errno
import random
import time

#HOST = socket.gethostbyname('cs5700cdnproject.ccs.neu.edu')
HOST = '129.10.117.186'
MAPPINGS_UPDATE_PORT = 51004
CLIENTS_BROADCAST_PORT = 51003


# Given: The data and address of the client
# Returns: Unpacks the data and flags 
class dns():

	def __init__(self,data,address, sock):
		self.flag = struct.Struct("!6H").unpack_from(data)[0]		
		self.id = struct.Struct("!6H").unpack_from(data)[1]
		self.question = struct.Struct("!6H").unpack_from(data)[2]
		self.answer = struct.Struct("!6H").unpack_from(data)[3]
		self.authority = struct.Struct("!6H").unpack_from(data)[4]		
		self.additional_info = struct.Struct("!6H").unpack_from(data)[5]		
		self.offset = None
		self.question_head = None
		self.qr= None
		self.opcode = None
		self.aa = None
		self.tc = None
		self.rd = None
		self.ra = None
		self.z = None
		self.rcode = None
		self.ques_type = None		
		self.ques_name = None
		self.ques_class = None
		self.sock = sock
		self.send_answer = True

		#print self.flag

		if ((self.flag & 0x8000) !=0):
			self.qr=1
		else: 
			self.qr=0
		self.opcode = ((self.flag & 0x7800) >>11)
		if ((self.flag & 0x400) !=0):
			self.aa= 1
		else:
			self.aa =0
		if ((self.flag & 0x200) !=0):
			self.tc= 1
		else: 
			self.tc =0
		if ((self.flag & 0x100) !=0):
			self.rd= 1
		else: 
			self.rd = 0
		if ((self.flag & 0x80) !=0):
			self.ra= 1
		else:
			self.rd = 0
		
		self.z= (self.flag & 0x70) >> 4
		if ((self.flag & 0xF) != 0):
			self.rcode = 1
		else:
			self.rcode = 0
		
		self.offset= struct.Struct("!6H").size
		self.question_head,self.offset = self.question_header(data,address)
		

		# Given: The data,offset value,question header and address of the client		
		# Returns: Unpacks the question and checks if the question is "cs5700cdn.example.com"
	def question_header(self,data,address):
		ques_header = struct.Struct('!2H')
		tot_ques = []
		for _ in range(self.question):
			self.ques_name, self.offset = get_value(self.offset, data)
			self.ques_type, self.ques_class = ques_header.unpack_from(data,self.offset)
			self.offset= self.offset + ques_header.size
						
			ques = { "domain_name": self.ques_name,
				 "domain_type" : self.ques_type,
				 "domain_class": self.ques_class}

			ques= self.ques_name
			if ques == [ "cs5700cdn", "example", "com"]:
				tot_ques.append(ques)
				return tot_ques, self.offset
			else:
				self.sock.sendto(data,address)
				self.send_answer = False
				return 0,0



	# Given: the data received from client and ip address of replica server
	# Returns: The DNS response section with the ip address in Answer section  
	def dns_response(self, data, mapping):
		try:
			answer = ''
			answer += data[:2] + "\x81\x80"
			answer += data[4:6] + data[4:6] + "\x00\x00\x00\x00"
			answer += data[12:]
			answer += "\xc0\x0c"
			answer += "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
			answer += str.join("",map(lambda(x): chr(int(x)),mapping.split('.'))) 
			return answer
		except: 
			sys.exit()


# Given: offset value and the data
# Returns: Returns the question name and the offset value
def get_value(offset,data):
	name=[]
	try:
		while True:
			size, =struct.unpack_from("!B",data,offset)
			
			
			if(0xC0 & size) == 0xC0:
				adr, = struct.unpack_from("!H", data, offset)
				offset = offset + 2
				return labels + get_value(adr & 0x3FFF, data), offset

			offset +=1
		
			if size ==0: 
				return name,offset
	
			name.append(*struct.unpack_from("!%ds" % size, data, offset))
			offset= offset+size
	except:
		sys.exit()

# Performs the DNS service
def service(s, data, addr, replicas):
	# Unpack the headers
	#dns_request(data, addr)
	global mappings, mappings_lock
	
	req_obj = dns(data,addr, s)

	ip = None

	
	with mappings_lock:
		try:
			value = mappings[addr[0]]
			ip = value[0]
#			print('Active measurement mapping! ' + ip)
	
		except KeyError:
#			print('No mapping found, assigning random replica server.')
			
			ip = replicas[random.randint(0, len(replicas)-1)]
#			mappings[addr[0]] = [ip, float('inf')]

	# Send the address of the replica server
	if req_obj.send_answer:
		response = req_obj.dns_response(data,ip)
		s.sendto(response,addr)
#	print('Serviced: ' + str(addr))
	
	

def translations(port, ns, replicas):
	global clients, clients_lock
	
	if ns == "cs5700cdn.example.com":
		try:	
			#UDP Socket Creation
			s= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			try:		
				#Binding with the IP Address where the DNS Server runs			
				#ip = socket.gethostbyname(HOST)
				#ip = socket.gethostbyname('localhost')	
				ip = HOST
				s.bind((ip,port))

			except socket.error,msg:
				print msg				
				sys.exit(1)
					
			while True:
#				print('Waiting for request')
				data,address= s.recvfrom(1024)
				
				with clients_lock:
					clients.add(address[0])
				
				t = threading.Thread(target=service, args=(s,data,address, replicas))
				t.start()
			
			
		except socket.error as e:
			print('socket error caught: ' + str(e))
			sys.exit(1)
	
	else:
		print "CLI Error" 			


# Starts off the threads responsible for active measurement
def active_measurements(replicas):
	t1 = threading.Thread(target=broadcast_new_clients, args=(replicas,))
	t2 = threading.Thread(target=updated_mappings, args=(replicas,))
	t1.start()
	t2.start()

# Broadcasts the current set of clients to all the replica
# servers with which connection is established.
# replicas -> 9-tuple of ip addresses as strings
def broadcast_new_clients(replicas):

	connections = []
	dead_connections = []
#	clients_encountered = None
	new_clients = None

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((socket.gethostbyname(HOST), CLIENTS_BROADCAST_PORT))
	s.setblocking(0)
	s.listen(len(replicas))

	global clients, clients_lock

	while True:
		if len(connections) != len(replicas):
			try:
				while True:
					conn, addr = s.accept()
					if addr[0] not in replicas:
						conn.close()
					else:
							connections.append(conn)
			except socket.error as e:
				pass
#		clients_encountered = set()
		
		new_clients = []

		with clients_lock:
			new_clients = clients.copy()


		try:	
			if new_clients != []:
				for conn in connections:
					try:
						conn.send(''.join(map(lambda x: x+'$', new_clients)))
					except socket.error as se:
						errnum = se.args[0]
						if errnum == errno.EPIPE:
							dead_connections.append(conn)		
		except socket.error:
			pass
		finally:
			for con in dead_connections:
				connections.remove(con)
			dead_connections = []
		time.sleep(3)

# Object representing a connection to a replica server
class rep_conn():
	def __init__(self, replica_ip):
		self.replica_ip = replica_ip
		self.conn = None
#		self.pipe = Queue.Queue()
		self.dict = {}
		self.connected = False
		self.buff_size = 65535
	
	def assign_connection(self, conn):
		self.conn = conn
		self.conn.setblocking(0)
		self.connected = True

	
	def update(self):
		values = None
		data = ''
		arrived = self.connected
		try:
			if self.connected:
				data += self.conn.recv(self.buff_size)
				arrived = True
#				print('Update recv: ' + data)
		except socket.error as se:
			errnum = se.args[0]
			if errnum == errno.EPIPE:
				self.connected = False
			elif errnum == errno.EWOULDBLOCK:
				arrived = False
		if arrived:
			self.__update_mappings__(data)
	

	def __update_mappings__(self, data):
		lines = filter(lambda x: x!='', data.split('\n'))
		for line in lines:
#			print('the line:' + line)
			ip, time = line.split()
			self.dict[ip] = float(time)


# Recieves updates from the replica servers and accordingly updates
# its current mappings for client ip addresses
def updated_mappings(replicas):
	
	connections = {}
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((HOST, MAPPINGS_UPDATE_PORT))
	s.setblocking(0)
	s.listen(len(replicas))

	global mappings, mappings_lock

	for ip in replicas:
		connections[ip] = rep_conn(ip)
#	pipes = []

	buff_size = 65535
#	for _ in range(len(replicas)):
#		pipes.append(Queue())
	
	while True:
		
		try:
			while not all(map(lambda x: x[1].connected, connections.items())):
				conn, addr = s.accept()
				if addr[0] not in replicas:
					conn.close()
				else:
					connections[addr[0]].assign_connection(conn)
		except socket.error as e:
			pass

		'''
		data = None
		start = int(time.time())
		now = 0
		has_data = None
		while (now - start) >= 5:
			try:
				has_data = True
				data, addr = s.recvfrom(buff_size)
			except socket.error as e:
				has_data = False
			if has_data:
				try:
					connections[addr[0]].update(data)
				except KeyError:
					pass
			now = int(time.time())
		'''

		keys_union = set()
		for ip, repcon in connections.items():
			repcon.update()
			keys_union = set.union(set(repcon.dict.keys()), keys_union)

		for ip, repcon in connections.items():
			d = repcon.dict
			for unmapped in (keys_union - set(d.keys())):
				d[unmapped] = float('inf')


		new_mappings = {}
		
		for key in keys_union:
			best_time = float('inf')
			best_ip = None
			for ip, repcon in connections.items():
				if repcon.dict[key] < best_time:
					best_time = repcon.dict[key]
					best_ip = ip
			if (best_time != float('inf')) and (best_ip != None):
				new_mappings[key] = [best_ip, best_time]

		with mappings_lock:
			for key in new_mappings.keys():
				try:
					if new_mappings[key][1] < mappings[key][1]:
						mappings[key] = new_mappings[key]
				except KeyError:  
					mappings[key] = new_mappings[key]
		time.sleep(3)

# Beginning of execution
def main():
	'''
	port_sym = sys.argv[1]
	port = int(sys.argv[2])
	url_sym = sys.argv[3]
	url = sys.argv[4]
	'''

	number_of_args = 4
	argv_1 = '-p'
	argv_3 = '-n'

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
		global MAPPINGS_UPDATE_PORT, CLIENTS_BROADCAST_PORT

		if port > 40000:
			if port > 50000:
				if port > 60000:
					if port > 2**16:
						pass
					else:
						#60k - 2**16
						MAPPINGS_UPDATE_PORT = port - 15328
						CLIENTS_BROADCAST_PORT = port - 15329
				else:
					#50k - 60k
					MAPPINGS_UPDATE_PORT = port - 10528
					CLIENTS_BROADCAST_PORT = port - 10529

			else:
				#40k-50k
				MAPPINGS_UPDATE_PORT = port + 15329
				CLIENTS_BROADCAST_PORT =  port + 15328
		else:
			#< 40k
			pass

		replicas = ('ec2-52-0-73-113.compute-1.amazonaws.com',
			'ec2-52-16-219-28.eu-west-1.compute.amazonaws.com',
			'ec2-52-11-8-29.us-west-2.compute.amazonaws.com',
			'ec2-52-8-12-101.us-west-1.compute.amazonaws.com',
			'ec2-52-28-48-84.eu-central-1.compute.amazonaws.com',
			'ec2-52-68-12-77.ap-northeast-1.compute.amazonaws.com',
			'ec2-52-74-143-5.ap-southeast-1.compute.amazonaws.com',
			'ec2-52-64-63-125.ap-southeast-2.compute.amazonaws.com',
			'ec2-54-94-214-108.sa-east-1.compute.amazonaws.com')

		replicas = tuple(map(socket.gethostbyname, list(replicas)))

		global clients, clients_lock, mappings, mappings_lock
		clients = set()
		clients_lock = threading.Lock()
		mappings = {}
		mappings_lock = threading.Lock()

		t1 = threading.Thread(target=translations, args=(port, sys.argv[4], replicas))
		t2 = threading.Thread(target=active_measurements, args=(replicas,))

		t1.start()
		t2.start()

if __name__ == '__main__':
	main()
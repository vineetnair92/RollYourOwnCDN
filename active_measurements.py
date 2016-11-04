import socket
import urlparse
import os
import sys
import threading
import Queue
import subprocess
import time
import errno

DNS_PORT_SEND = 51004
DNS_PORT_RECV = 51003

DNS_HOST = socket.gethostbyname('cs5700cdnproject.ccs.neu.edu')

# Initiates active measurements
def active_measurements():
	pipe = Queue.Queue()
	
#	global clients, clients_lock
#	clients = set()
#	clients_lock = threading.Lock()

#	t1 = threading.Thread(target=get_new_clients, args=(pipe,))
#	t2 = threading.Thread(target=send_measurements, args=(pipe,))

	global dns_socket_send
	dns_socket_send = dns_socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	get_new_clients(pipe)
#	t1.start()
#	t2.start()


#data format: 'token1$token2$tokenn'
# Fetches data from DNS server.
def get_new_clients(pipe):
	connected = False
	new = ''
	data = None
	dns_socket_recv = None
	buff_size = 65535
	clients = set()

	while True:
		if not connected:
			try:
				dns_socket_recv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				dns_socket_recv.connect((DNS_HOST, DNS_PORT_RECV))
				dns_socket_recv.setblocking(0)
				connected = True
			except socket.error as e:
				pass
		try:
			if connected:
				data = dns_socket_recv.recv(buff_size)
				new = data
#				print('Recieved from DNS: ' + data)
		except socket.error as se:
			errnum = se.args[0]
			if errnum == errno.EPIPE:
				connected = False
#		print('this:' + str(new))

		if new != '':
#			print(new)
#			time.sleep(3)
			new = filter(lambda x: x!='', new.split('$'))

			for ip in new:
#				if ip not in clients:
#					print('new ip: ' + ip)
				clients.add(ip)
			new = ''
		if len(clients) > 0:
			send_measurements(clients)

#			if pipe.empty():
#				pipe.put(clients)
#			new = ''

#			print(list(pipe.queue))
#		if data == '':
#			connected = False

# Sends back the scamper ping results to DNS server.
def send_measurements(ip_list):
	fp = open('ips', 'w+')
	fp.write('\n')
	fp.close()

	connected = True
	results = ''

	global dns_socket_send

	while True:
		
		if len(ip_list) > 0:
#			print('in')
			results = scamper(list(ip_list))
		try:
			dns_socket_send.send(results)
		except socket.error as se:
			errnum = se.args[0]
			if errnum == errno.EPIPE:
				connected = False

		if len(ip_list) > 0:
			fp = open('ips', 'w+')
			fp.write(str(results) + '\n')
			fp.close()
#			print('Scamper results:\n' + str(results))

		if not connected:
			try:
				dns_socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				dns_socket_send.connect((DNS_HOST, DNS_PORT_SEND))
				connected = True
#				print('send_measurements: connected')
			except socket.error as e:
				pass
		else:
			break

# Executes a command as a subprocess.
def execute_command(command):
	#import subprocess
	return subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)

# Gives the result from the scamper pings to the given list of IPs.
def scamper(ip_list):
	comm = '/usr/local/bin/scamper -c "ping -c 1" -p 1 -i ' + ' '.join(ip_list)
	results = execute_command(comm)
	return data_from_results(results)

# Parses the scamper results and fetches the data.
def data_from_results(results):
	results = results.split('\n')
	data = ''
	length = len(results)
	i = 0
	packets_delivered = None
	while i < length: 
		if results[i].startswith('--- '):
			data += results[i].split()[1] + ' '
			packets_delivered = results[i+1].split()[3]
			if packets_delivered == '0':
				data += 'inf'
				i += 2
			elif packets_delivered == '1':
				data += results[i+2].split(' = ')[1].split('/')[0] + '\n'
				i += 3
		else:
			i += 1
	return data

# Beginning of execution,
def main():

	port = int(sys.argv[1])

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
#	print('1:' + str(DNS_PORT_SEND))
#	print('2:' + str(DNS_PORT_RECV))
	active_measurements()

if __name__ == '__main__':
	main()
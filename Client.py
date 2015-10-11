__author__ = 'gh.liang0910@gmail.com'
"""This is the client program accords to the requirements of HW1,"""
"""which achieves functions namely,"""

import socket
import sys
from threading import Thread
from threading import ThreadError
import time
import thread

# -----------GLOBALS----------------------- #
# global variables
connection_status = bool(False)

# time of attempt to open socket
SOCKET_ATTEMPTS = 3
# time interval for next socket try, seconds
INTERVAL_ATTEMPTS = 1

# Time interval for main thread to check user status, seconds
INTERVAL_CHECK = 1

# Idle time to logout client automatically
IDLE_TIME = 30
RECEIVE_INTERVAL = 0.01

# CONNECTION STATUS 1 means connection successfully, 0 means connection fails.
CONNECTION_OK = True
CONNECTION_FAIL = False


# --------------Client---------------------- #
class Client:
    def __init__(self,  client_socket=None, host_name='COMS4119', port_number='4119'):
        self.client_socket = client_socket  # socket instance used to connection with server
        self.host_name = host_name  # server ip or alias name to connect with
        self.port_number = port_number  # server port number
        self.message_idle = list()  # a list to receive the idle message
        self.thread_service = {'receive': None, 'send': None, 'idler': None}    # a dict to manage all threads
        self.user_name = 'client'   # initial name of this client, after log in, this filed will be user name.
        self.thread_status = False  # flag to control all the threads

    def is_port_number(self, port_number):
        try:
            self.port_number = port_number
            int(self.port_number)
            return True
        except ValueError:
            return False

    def set_thread_status(self, flag):
        self.thread_status = flag

    def set_host_name(self, host_name):
        self.host_name = host_name

    def set_port_number(self, port_number):
        self.port_number = port_number

    def message_sender(self):
        while self.thread_status:
            try:
                message = raw_input("<'' or ENTER won't be sent" + '> ')
                self.client_socket.send(message)
                # avoid multiple message send together in the buffer.
                time.sleep(0.01)
            except socket.error:
                print 'Fail to send message, socket closed already, press CTRL + C to exit.\n'
                self.set_thread_status(False)
                thread.exit()

        print 'client_sender thread: no socket available, exiting now...press ENTER for more info.\n'
        thread.exit()

    def receive_message(self):
        """receive and handle some feed back by server."""
        while self.thread_status:
            try:
                # time.sleep(RECEIVE_INTERVAL)    # give time for message to come in the queue.
                # this will cause some buffer to blow together
                temp = self.client_socket.recv(1024)
                message = temp.split()
                if not message:
                    print 'Socket to the server is broken.\n'
                    # print message
                    self.set_thread_status(False)   # terminate the loop and exit all threads
                elif message[0] == 'logout':
                    self.set_thread_status(False)
                    print("log out successfully by request or server.\n press CTRL + C to exit :)\n")
                elif temp.find('idle')+1:
                    self.message_idle.append('idle')
                    for v in temp.split('idle'):
                        print self.user_name + ': ' + v
                elif message[0] == 'NAME':
                    self.user_name = message[1]
                elif message[0] == "LOGIN":
                    print '\n' + 'LOGIN SUCCESSFULLY'.center(40, '-') + '\n'
                else:
                    print self.user_name + ' ->  ' + temp

            except socket.error:
                print 'socket is down\n'
                self.set_thread_status(False)
                thread.exit()

        print 'receive_message thread: exiting now... press ENTER for more info.\n'
        self.close()  # only one thread has close() to avoid closing socket duplicate times.

    def client_idler(self):
        while self.thread_status:
            if self.message_idle:
                self.client_socket.send(self.message_idle.pop(0))
                time.sleep(1)

        print 'client_idler thread: exiting now...press ENTER for more info.'
        thread.exit()

    def close(self):
        self.set_thread_status(False)
        self.client_socket.close()
        thread.exit()

# -----------------MAIN--------------------- #
if __name__ == '__main__':
    client = Client()

    # set up TCP connection.
    print 'PRESS CTRL + C TO EXIST ANYTIME'
    # Check whether the host can open sockets

    for i in xrange(SOCKET_ATTEMPTS):
        try:
            client.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            break
        except socket.error as msg:
            if i == SOCKET_ATTEMPTS - 1:
                print('Fail to open socket' + str(msg[0]) + '\nError message:' + msg[1])
                sys.exit(-1)
        time.sleep(INTERVAL_ATTEMPTS)
    # Successfully open a socket

    HOST = sys.argv[1]
    PORT = sys.argv[2]

    while connection_status == CONNECTION_FAIL:
        try:
            # back to the end to get arg[] type
            client.set_host_name(HOST)
            valid_port_num = False

            # this while loop only cares about the port number
            while not valid_port_num:
                valid_port_num = client.is_port_number(PORT)
                if valid_port_num:
                    try:
                        PORT = int(PORT)
                        client.client_socket.connect((HOST, PORT))
                        client.set_port_number(PORT)
                        client.set_thread_status(True)  # allow valid socket to establish threads
                        connection_status = CONNECTION_OK
                        print ('Connection to ' + HOST + ' successfully.').center(60, '-') + '\n'
                    except KeyboardInterrupt:       # In case a keyboard interrupt occurs
                        print('Client program is terminated by Ctrl + C.\n')
                        sys.exit('KeyboardInterrupt @ socket.connect')
                    except socket.herror, e:
                        # socket.error will return (errno, str)
                        print 'Host name(address error): #{0}, {1}.\n'.format(e[0], e[1])
                        break
                    except socket.error, e:
                        print 'Socket error: #{0}, {1}.\n'.format(e[0], e[1])
                        break
                    except:     # Handle other Exceptions except KeyboardInterrupt
                        print 'Type or Value error .etc' + '\n'
                else:
                    print 'Invalid port number: not an integer. please try again\n\n'
                    PORT = raw_input("Input port number (integer required): ")

            if not connection_status:
                print "host name or port number error, please try again, CTRL + C to exit.\n"
                HOST = raw_input("Input the host name: ")
                PORT = raw_input("Input port number (integer required): ")

        except KeyboardInterrupt:       # In case a keyboard interrupt occurs
            print('Client program is terminated by Ctrl + C.\n')
            sys.exit(-1)
        except Exception:     # In case other exceptions occurs
            print 'Exception occurs while trying to connect'
            print '\nattempt to connect again\n'
            connection_status = CONNECTION_FAIL

    try:
        # start three threads to handle message receives, send, and reply idle message.
        # receiver thread
        client_receiver = Thread(target=client.receive_message)
        client.thread_service['receive'] = client_receiver
        client_receiver.setDaemon(True)
        client_receiver.start()
        # sender thread
        client_sender = Thread(target=client.message_sender)
        client.thread_service['send'] = client_sender
        client_sender.setDaemon(True)
        client_sender.start()

        # idler thread
        client_idler = Thread(target=client.client_idler)
        client.thread_service['idler'] = client_idler
        client_idler.setDaemon(True)
        client_idler.start()

    except ThreadError, e:
        print 'Fail to open thread. Error: #{0}, {1}'.format(str(e[0]), e[1])
        client.client_socket.close()
        sys.exit('Thread Fail')

    while True:
        try:
            time.sleep(INTERVAL_CHECK)
            if connection_status == CONNECTION_FAIL:
                sys.exit()
        except KeyboardInterrupt:
            print('Client program is terminated by Ctrl + C.\n')
            try:
                client.client_socket.send('logout')
                client.close()
            except socket.error:
                print 'socket already closed or broken.\n'
            sys.exit(0)
        except socket.error:
            print('')
        except Exception, e:
            print e
            print ' Inner Exception occurs'
            sys.exit(-1)




                










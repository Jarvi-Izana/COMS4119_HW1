from threading import Thread
import socket
import time
import sys
import thread
# GLOBAL VARIABLES
SERVER_IDLE = 30
# Status
ERROR = -1
OK = 1
EMPTY = 0
OFFLINE = 0
ONLINE = 1
NO_SERVICE = False
BLOCK_TIME = 60

# auto log out if 30 minutes without activity
TIME_OUT = 1800

# idle timer interval
IDLE = 60


def get_local_time():
    """convert time to yyyy/mm/dd hours:minutes:secs"""
    local_time = time.localtime()
    return "{0}/{1}/{2} {3}:{4}:{5} ".format(local_time[0], local_time[1], local_time[2],
                                             local_time[3], local_time[4], local_time[5])


# ------------------------CLASS--------------------------------- #


class ClientInfo:
    """ Client information: password, message box, time out timer, ip info
        Only if the user log in, will this instance be invoked.
    """

    def __init__(self, name, password, ip, connection_socket=None):
        """(Clientinfo, str, str) -> NoneType

            Create a data set of a client's information, which includes name,
            password, message, timeout timer, online status, and IP address.
        """
        self.name = name
        self.password = password
        self.message_box = list()
        self.message_send = list()
        self.time = time.time()  # this is login time, won't change in the future.
        self.idle_time = self.time  # used to compute idle time to logout
        self.active_time = self.time
        self.thread_status = False
        self.online_status = False
        self.ip = ip
        self.connection_socket = connection_socket
        # Three types of function use thread services
        self.thread_in_service = dict(receiver=None, sender=None, timer=None)
        # self.inner_logout = False  # without sending logout but with hard shut down.

    def get_name(self):
        return self.name

    def get_password(self):
        return self.password

    def set_password(self, new_password):
        if isinstance(new_password, str) and len(new_password) > 0:
            self.password = new_password
            return OK
        else:
            return ERROR

    def set_idle_time(self, time_):
        self.idle_time = time_

    def get_idle_time(self):
        return self.idle_time

    def get_active_time(self):
        return self.active_time

    def set_active_time(self, time_):
        self.active_time = time_

    def get_time(self):
        return self.time

    def set_time(self):
        self.time = time.time()

    def get_online_status(self):
        return self.online_status

    def set_online_status(self, flag):
        self.online_status = flag

    def pop_message_box(self):
        """C.pop_message() -> item"""
        if len(self.message_box) > 0:
            return self.message_box.pop(0)
        else:
            # no message will return
            print 'Mailbox empty\n'
            return EMPTY

    def push_message_send(self, message):
        """push message into message_send of client to send message: item -> None"""
        return self.message_send.append(message)

    def push_message_box(self, message):
        """push message into message box of client: item -> None"""
        return self.message_box.append(message)

    def get_ip(self):
        return self.ip

    def get_thread_status(self):
        """C.get_status() -> bool, (0) or ONLINE(1)"""
        return self.thread_status

    def set_thread_status(self, status):
        self.thread_status = status

    def set_service(self, usage_message, thread_service):
        """
        :param usage_message: str
        :param thread_service: threading.Thread
        :return: bool
        """
        if usage_message in self.thread_in_service.keys():
            self.thread_in_service[usage_message] = thread_service
            return OK
        return NO_SERVICE

    def close_thread(self):
        """close all the service thread"""
        self.set_thread_status(False)

    # this is sub thread for preprocessing
    def client_receiver(self):
        """ receives message from client"""
        while self.thread_status:
            if not self.message_box:
                try:
                    temp = self.connection_socket.recv(1024)
                except socket.error:
                    # connection reset or broken.
                    self.message_box.append('logout')
                    break

                # avoid 'idle' mixes with the user message.
                if temp:
                    if temp.find('idle') + 1:
                        for v in temp.split('idle'):
                            self.message_box.append(v)
                            print self.name + ': ' + v
                    else:
                        print self.name + ': ' + temp
                        self.message_box.append(temp)
                        # do not pop your data, this job must be done by main thread.
                        # elif temp == 'idle':
                        # self.time = time.time()
                elif temp == 'idle':
                    self.message_send.append('idle')
                else:
                    # self.set_thread_status(False)
                    # self.inner_logout = True  # connection shuts down due to client hard log out
                    # self.connection_socket.close()

                    # in case for a user hard exit, which means socket broken not by user CTRL + C
                    # let the manager to close all the stuff
                    self.message_box.append('logout')
                    # break  # connection is broken, just close the socket.

        print get_local_time() + self.name + ' log out, client_receiver exiting...\n'
        self.close()

    def client_sender(self):

        while self.thread_status:
            if self.message_send:
                try:
                    self.connection_socket.send(self.message_send.pop(0))
                except socket.error:
                    break

        print get_local_time() + self.name + ' log out, client_sender exiting...\n'
        thread.exit()

    # check the TCP connection is sound and good
    def client_timer(self):
        while self.thread_status:
            time.sleep(IDLE)
            current = time.time()
            if (current - self.idle_time) < 300:
                self.message_send.append('idle')
            else:
                self.set_thread_status(False)

        print get_local_time() + self.name + ' log out, client_idler exits...\n'
        thread.exit()

    def close(self):
        # self.set_thread_status(False)
        # self.set_online_status(False)
        self.connection_socket.close()


# This is the user info dictionary with Username-Password

class Server:
    def __init__(self, server_name='localhost', port_number=4119):
        self.server_name = server_name
        self.port_number = port_number
        self._client_list = dict()  # user name online: ClientInfo()
        self.listen_number = 20
        self.block_list = {}    # storing the name and blocking start time.
        # self.command_queue = [] future use
        self.authorized_users = {
            'facebook': 'wastetime',
            'network': 'seemsez',
            'foobar': 'passpass',
            'wikipedia': 'donation',
            'google': 'partofalphabet',
            'windows': 'withglass',
            'csee4119': 'lotsofassignments',
            'seas': 'summerisover',
            'columbia': '116way'
        }
        # self.command = ('logout', 'wholelse', 'wholast', 'braodcast', 'message')
        self.offline_box = dict()
        self.init_offline_box()
        # Initialize a IPv4 server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server_socket.bind((self.server_name, self.port_number))
        except socket.gaierror:
            sys.exit('no such host name or ip\n')
        except socket.error:
            sys.exit('host name or port number unknown.\n')
        self.server_socket.listen(self.listen_number)

    def init_offline_box(self):
        for key in self.authorized_users.keys():
            self.offline_box[key] = []  # user_name : list()
        # print self.offline_box
        return None

    def close(self):
        """ S.close() -> None
            close the server
        """
        for user in self._client_list.keys():
            self._client_list[user].push_message_send('logout')
            self._client_list[user].set_thread_status(False)

        self.server_socket.close()

    def send_to(self, user_name, message):
        """
        send message to certain valid user.
        :rtype : None
        """
        self._client_list[user_name].message_send.append(message)

    def is_user_valid(self, user_name, password):
        """ S.is_valid_user(str, str) -> bool
            Check whether the user is valid or not
        """
        if user_name in self.authorized_users:
            if self.authorized_users[user_name] == password:
                return True
        return False

    def read_user_info(self, path='user_pass.txt'):
        """ read profile user_pass.txt by default
            S.read_usr_password(str) -> None
        """
        user_password = dict()
        try:
            with open(path) as user_file:
                lines = user_file.readlines()
                for line in lines:
                    line = line.split()
                    if len(line) == 2:
                        user_password.setdefault(line[0], line[1])
                    else:
                        print 'Tolerant fault: user password format error:' + line + '\n'
        except IOError as msg:
            print 'No such a file: ' + path + '\nError message {0}: {1}\n'.format(msg[0], msg[1])
            sys.exit('file load fail @Server @read_user_info')

        if user_password != dict():
            self.authorized_users = user_password
            self.init_offline_box()

    def print_user_info(self):
        print 'registered users:\n' + str(self.authorized_users.keys()) + '\n'

    def is_blocked(self, unauthorized_name):
        if unauthorized_name in self.block_list:
            if (time.time() - self.block_list[unauthorized_name]) < BLOCK_TIME:
                return True
            else:
                self.block_list.pop(unauthorized_name)
        return False

    # check whether the user is on line.
    def is_user_in_cache(self, user_name):
        """check whether the user has logged in before and left cache"""
        if user_name in self._client_list.keys():
            return True
        return False

    def is_user_exist(self, user_name):
        """ S.is_user_exist() -> None
            Check whether user is in the _client_list
        :rtype : bool
        """
        if user_name in self.authorized_users:
            return True
        return False

    def is_user_login(self, user_name):
        if user_name in self._client_list:
            return self._client_list[user_name].get_status()
        return OFFLINE

    def push_offline_box(self, user_name, offline_message):
        """

        :param user_name: str
        :param offline_message: str
        :return: None
        """
        if self.is_user_exist(user_name):
            self.offline_box[user_name].append(offline_message)

    # this method will be invoked every time a user is online to fetch his offline message.
    def fetch_offline_box(self, user_name):
        """

        :rtype : str
        """
        try:
            return self.offline_box[user_name][0]
        except IndexError:
            return ''

    def pop_offline_box(self, user_name):
        """

        :param user_name: str
        :return: str
        """
        try:
            return self.offline_box[user_name].pop(0)
        except IndexError:
            return ''

    def accept(self, user_name_message='Username: ',
               password_message='Password: '):
        connection_socket, address = self.server_socket.accept()
        print get_local_time() + str(address) + ' attempts to login \n'

        duplicate = 0
        for i in xrange(3):
            connection_socket.send(user_name_message)
            login_message = connection_socket.recv(1024)
            # detect whether user is in the block list.
            if not self.is_blocked(login_message):
                # detect whether the user is authorized user
                if self.is_user_exist(login_message):
                    # detect duplicate log in
                    if not self.is_user_in_cache(login_message):
                        connection_socket.send(password_message)

                        try:
                            connection_socket.settimeout(180)
                            password = connection_socket.recv(1024)

                            if self.is_user_valid(login_message, password):
                                connection_socket.send('LOGIN')
                                time.sleep(0.5)
                                connection_socket.send(login_message + ' login\n')
                                self.user_login_alloc(login_message, password, address, connection_socket)
                                # skip all the steps left.
                                return None
                            else:
                                # duplicate log in
                                connection_socket.send('Password is incorrect. ' + "please try again, " +
                                                       str(2 - i) + ' times left\n')
                                continue
                        except socket.timeout:
                            connection_socket.send('time out.')
                            connection_socket.close()

                    else:
                        connection_socket.send('Already log in, logout first.\n')
                        duplicate = i
                        continue
                else:
                    connection_socket.send("User name doesn't exist, please try again. " + str(2 - i) +
                                           ' time(s) left\n')
            else:
                break  # in the block list

        # if duplicate at the last log in step (duplicate = 2), the connection will close.
        if duplicate < 2:
            connection_socket.send(('Unauthorized user, connection reject. User will be blocked for {0} seconds ' +
                                    'Press ENTER for more information.\n').format(BLOCK_TIME))
            self.block_list.setdefault(login_message, time.time())
        else:
            connection_socket.send('Connection rejected: Already log in\n')

        connection_socket.close()

        return None

    def user_login_alloc(self, user_name, password, address, connection_socket):
        # add to the server dict to check the status of all the socket ongoing.
        # not sure whether to add user_name attr to the ClientInfo or not,
        # because I use user command manager to control user info.
        # Since the data structure of user:ClientInfo already maps the name with its
        # instance.
        self._client_list.setdefault(user_name,
                                     ClientInfo(user_name, password, address[0], connection_socket))
        client = self._client_list[user_name]
        client.set_thread_status(True)
        client.set_online_status(True)
        print get_local_time() + str(address) + ' ' + user_name + ' login \n'

        manager = Thread(target=self.command_manager, args=(user_name,))
        manager.setDaemon(True)
        manager.start()

        receiver = Thread(target=client.client_receiver)
        receiver.setDaemon(True)
        client.thread_in_service['receiver'] = receiver
        receiver.start()

        sender = Thread(target=client.client_sender, args=client.message_box)
        sender.setDaemon(True)
        client.thread_in_service['sender'] = sender
        sender.start()

        timer = Thread(target=client.client_timer)
        timer.setDaemon(True)
        client.thread_in_service['timer'] = timer
        timer.start()

    # ----------------COMMANDS-------------------- #

    def command_manager(self, user_name):
        # this user_name is the sender's user_name, make sure that to avoid send message to yourself
        manager = self._client_list[user_name]
        online = manager.get_online_status()

        # send login user name to the user.
        try:
            self.send_to(user_name, 'NAME  ' + user_name)
        except socket.error:
            self.close()

        # when user online, the offline message will send to user automatically.
        offline_message = self.fetch_offline_box(user_name)
        while offline_message and online:
            # send offline messages.
            # offline_message must bot be any type of None [], otherwise will cause sender to exit.
            manager.message_send.append(offline_message)
            self.pop_offline_box(user_name)
            offline_message = self.fetch_offline_box(user_name)

        # user must be online to receive offline message and commands

        while online:
            if not manager.message_box:
                time.sleep(0.1)
                # automatically logout the user when no message send to the user.
                if (time.time() - manager.get_active_time()) > TIME_OUT:
                    manager.message_send.append('logout')
                    print get_local_time() + "automatically log out " \
                                             "with no action within {0} minutes\N".format(TIME_OUT)
            else:
                # command should be list of sub command
                message = manager.message_box.pop()
                command = message.split()
                # in case the message is whitespace
                try:
                    header = command[0]
                except IndexError:
                    # whitespace message
                    continue
                # print header
                if header == 'idle' and len(command) == 1:
                    manager.set_idle_time(time.time())
                else:
                    manager.set_active_time(time.time())
                    if header == 'logout' and len(command) == 1:
                        try:
                            manager.message_send.append('logout')
                        except socket.error:
                            print user_name + ' hard exit.\n'
                        self.logout(user_name)
                    elif header.startswith('who'):
                        if header == 'whoelse' and len(command) == 1:
                            self.send_to(user_name, self.whoelse(user_name))
                        elif header.startswith('wholast'):
                            self.send_to(user_name, self.wholast(command))
                        else:
                            self.send_to(user_name, 'Do you mean whoelse or wholast?\n')
                    elif header == 'broadcast':  # check command items inside
                        self.broadcast(user_name, message)
                    elif header == 'message':  # check command items inside
                        self.message(user_name, message)

        print get_local_time() + user_name + ' log out, corresponding thread manager exiting...'
        thread.exit()

    def logout(self, user_name):
        print get_local_time() + '{0} log out by request\n'.format(user_name)
        # try:
        # print self._client_list
        # minor bug here, logout may run twice.
        try:
            self._client_list[user_name].set_thread_status(False)
            self._client_list[user_name].set_online_status(False)
            self._client_list.pop(user_name)
        except KeyError:
            # print e
            # print 'S.logout #{0}'.format(str(e[0]))
            pass

    def whoelse(self, user_name):
        who_else = ''
        for name in self._client_list.keys():
            if name != user_name:
                who_else += name + ' '
        if who_else.split():
            return who_else + '\n'
        else:
            return 'You are alone, bro :) Just talk to server or leave offline message to other users.\n'

    def wholast(self, command):
        if len(command) == 2:
            try:
                temp = float(command[1])
                if temp >= 60 or temp < 0:
                    return 'number must between 0 and 60\n'
                else:
                    last_user = ''
                    # for k, v in self._client_list: if you don't use .items(), error will raise.
                    for k, v in self._client_list.items():
                        if (time.time() - self._client_list[k].get_time()) / 60.0 < temp:
                            last_user += v.get_name() + ' '

                    if not last_user:
                        return 'No one login within last %.2f minutes' % temp
                    else:
                        return last_user + '\n'
            except KeyError:
                return 'argument 2 must between 0 and 60, e.g. wholast 32\n'
        else:
            return 'syntax error, make sure format like this: wholast 32\n'

    def message(self, user_name, message, mode='message'):
        """
        :type user_name: str the sender's info
        :param message: str, the original message the user receives
        :return: None
        """
        command = message.split()
        try:
            message = message[(message.find(command[1]) + len(command[1])):].strip()
            # if don't have message target, return error message info to users
            if self.is_user_in_cache(command[1]):
                # the message part, strip all tail and lean whitespace
                if message:
                    # print message + '\n'
                    self.send_to(command[1], get_local_time() + user_name + " private msg: " + message + '\n')
                else:
                    self.send_to(user_name, 'Invalid message, type the message to send separates with space.\n')
            elif self.is_user_exist(command[1]):
                # pass  # for off line message sending
                self.send_to(user_name,
                             "{0} is offline. Message will be saved to {0}'s offline box.\n".format(command[1]))
                self.push_offline_box(command[1], get_local_time() + user_name + ' private msg: ' + message + '\n')
            else:
                self.send_to(user_name, mode + ': invalid User name.\n')
        except IndexError:
            self.send_to(user_name, 'Lacks arguments. Make sure you have username and message content.\n')

    def broadcast(self, user_name, message):
        """
        broad cast to users that online or include offline
        :param user_name: str
        :param message: str
        :return: None
        """
        command = message.split()
        length = len(command)
        if length == 1:
            self.send_to(user_name, "More arguments needed for 'broadcast': broadcast <all> <user> <msg>\n")
        elif length == 2:
            # send message to whom is online.
            for user in self._client_list.keys():
                if user != user_name:
                    self.send_to(user, get_local_time() + user_name + ' broadcast msg: ' + command[1] + '\n')
        elif length > 2:
            if command[1] == 'all':
                # send message to all the authorized users
                temp = message[message.find('all') + 3:].strip()
                for user in self.authorized_users.keys():
                    if user in self._client_list.keys():
                        if user != user_name:
                            self.send_to(user, get_local_time() + user_name + ' broadcast msg: ' + temp + '\n')
                    else:
                        self.send_to(user_name,
                                     "{0} is offline. Message will be saved to {0}'s offline box.\n".format(user))
                        self.push_offline_box(user, get_local_time() + user_name + ' broadcast msg: ' + temp + '\n')
            else:
                # count how many users in the user field. The first user name must valid.
                i = 1
                while self.is_user_exist(command[i]):
                    i += 1

                if length > i > 1:  # we have i-1 valid users in command, and the rest are msg.
                    temp = message[(message.find(command[i - 1]) + len(command[i - 1])):].strip()
                    for j in xrange(i - 1):
                        if command[j + 1] in self._client_list.keys():
                            if command[j + 1] != user_name:
                                self.send_to(command[j + 1], get_local_time() + user_name + ' broadcast: ' + temp + '\n')
                        else:
                            self.send_to(user_name,
                                         "{0} is offline. Message will be saved to {0}'s offline box.\n".format(
                                             command[j+1]))
                            self.push_offline_box(command[j + 1], get_local_time() + user_name +
                                                  " broadcast: " + temp + '\n')
                else:
                    self.send_to(user_name, 'Invalid user name or no message field.\n')

    def server_close(self):
        """
        send logout to all the user online
        :return:
        """
        for user in self._client_list.keys():
            self.send_to(user, '\n' + 'Server Logout'.center(40, '-') + '\n')
            self.send_to(user, 'logout')


# --------------MAIN-------------------------- #
if __name__ == '__main__':
    try:
        server = Server(server_name=sys.argv[1], port_number=int(sys.argv[2]))
    except ValueError:
        sys.exit('port must be integer.')
    except IndexError:
        sys.exit('missing arguments.')

    server.read_user_info()  # use the file user_pass.txt
    server.print_user_info()
    # print server.authorized_users
    while True:
        try:
            server.accept()
        except (KeyboardInterrupt, socket.error):
            print 'Server Logout.\n'
            server.server_close()  # send logout message to all the users who login
            print 'Terminated by CTRL + C.\n'
            sys.exit(0)
        except Exception, e:
            print e
            sys.exit(' Unexpected exception caused by accept() loop.\n')

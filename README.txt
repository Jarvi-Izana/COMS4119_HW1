1,DESCRIPTION OF CODE
My code has two parts, the Cient part and the Server part.
1, Cient.py

1.1, Client class
1.1.1 Name field
client_socket = client_socket  # socket instance used to connection with server
host_name = host_name  # server ip or alias name to connect with
port_number = port_number  # server port number
message_idle = list()  # a list to receive the idle message
thread_service = {'receive': None, 'send': None, 'idler': None}    # a dict to manage all threads
user_name = 'client'   # initial name of this client, after log in, this filed will be user name.
thread_status = False  # flag to control all the threads

note: the message_idle is a list, when the list isn't empty, the message will immediately pop and send back to server.

1.1.2 important functions
All these service function is controlled by thread_status: while self.thread_status. If socket.recv() returns '' (same as socket is broken), or receives 'logout' (server force to log out), or user send 'logout' to the server, the thread_status will set False to stop all the threads and close socket wait for CTRL + C to exit.

message_sender: get input from the user and send the message to the user immediately.
receive_message: receive message from the server side, meanwhile do procession on the message received. For instance, if receive message 'logout' from server, which means that the server logs out, and correspondingly, the user will log out next. 
client_idler: handle with 'idle' things mentioned at the extra functionalities part.

1.1.2 main
when user log out by CTRL + C, the client will automatically send 'logout' to the sever to log out himself. If connection to the server is broken, the server and client can find this by themselves, and the detection is set inside of the functions by detecting socket.error or by check whether the socket.recv() returns '' all the time.

And in main, we allocate three different threads to simultaneously handle with message interacting with server.

2.2 Server
2.2.1 ClientInfo class
This class contains all the client information, such as user name, ip, online status. The most important of Client variable design is as follow:

self.connection_socket = connection_socket
This variable will store the socket object given by socket.accept(). This is the socket object that communicates with the client.

self.message_box = list()
self.message_send = list()
These two class variable is like buffers, storing the message comes and out. When client sends message to the server, the message will be stored at this buffer. And server will then handle with the data in the buffer. And the message_send is stored with the message to send. Once the message in the buffer is not empty, the thread to send message will immediately send it to corresponding client.

self.thread_in_service = dict(receiver=None, sender=None, timer=None)
A ClientInfo instance will have three thread to do receive, send, status check, which is similar to the Client class method for receiving, sending, timing.

2.2.2 Server class
(1) important variables 
self.block_list: used to store the blocked user names and block starting time.
self.authorized_users: used to store all the valid user names with their password. And this info can be read at the 'user_pass.txt'. If no .txt, server will use default user-password information.
self.offline_box = dict(), self.init_offline_box(): { key : [buffer]}, used to push all the offline message.

(2) important method
def accept(): deal with all the things relevant to user log in, and initialize the Server instance with corresponding ClientInfo instance and serving threads.

def user_login_alloc(self, user_name, password, address, connection_socket): Allocate thread to a ClientInfo instance and stores username to recognize specific users.

def command_manager(self, user_name) : 
first:
# send login user name to the user.
        try:
            self.send_to(user_name, 'NAME  ' + user_name)
        except socket.error:
            self.close()
This code will let the client know his name when log in. You will see, at first, at client your name is Client, after log in, your name will be your user name.

second:
check offline box and send off line message to the user when he logs in

Third: 
A while loop: handle with all the commands such as whoelse, message, etc. This method will take message at the ClientInfo.message_box buffer, then deal with the message, and finally push the response ClientInfo.message_send, which will be immediately sent by ClientInfo.client_sender.

def logout, message, wholast, whoelse, broadcast are these functions required as assignments to respond with certain command.

When server log out, 'logout' will send to user online and force them to log out. 


2,DETAILS AND DEVELOPMENT ENVIRONMENT
MAC OS X
Python 2.7.10

3,INSTRUCTION ON HOW TO RUN YOUR CODE

basic interface print:
username(at first will be Client) -> message time sender send_type(broadcast or msg): msg 
windows ->  2015/10/9 17:12:1 Guihao:  hehe

windows ->  2015/10/9 17:12:18 Guihao broadcast msg: heheh

basic interface input:
<'' or ENTER won't be sent>

Under the path where the .py is there.
(1)First you should launch the server with command: python Server.py host_name port_number. Make sure your port number is an integer, otherwise the program will exit with message to remind you this constraint.
(2)Then, you should run the Client.py with command: python Client.py host_name( or IP address) port_number. The host_name and port_number are strictly the same with your server's host_name and port_number.

HINT:If you launch the Client.py first, that's OK, but the thing is, the program will let you input number or name over and over again until a TCP connection with the server is established.

4,SIMPLE COMMANDS TO INVOKE YOUR CODE
(I) client log in: 3 times trial, duplicate log in detection, unauthorized user block out.

(0) server: BLOCK_TIME, TIME_OUT

(1) Launch server
cmd: python Server.py localhost 4119
And user names in the user_pass.txt will prompt at the terminal to guide you log with valid user names. On the server side, all the message sent to server will be displayed on the server side terminal.

And you can change block time and time out time by changing BLOCK_TIME, TIME_OUT respectively.

(2)Launch your clients.
cmd: python Client.py localhost 4119
Hints about a successful three-way handshake will prompt, then follow instruction to enter your user name and password. Only have three times to log in.

Once you log in, here's meaningful instruction set you can get feed back by the server side:
1, message user_name msg 
If user_name is valid and online, the message will send to user_name immediately. If user_name is valid but offline, the message will be saved to offline box of the server. Once the corresponding user_name logging in, offline message will send to the user immediately.

2, broadcast all user_names msg
here, the broadcast will also broad to yourself, and it's easy to block yourself.
2.1, broadcast all msg 
This will send msg to all users, if offline, msg will be saved to offline box.
2.2, broadcast user_name user_name ... message 
This command will send message to specific users with message. The same, if offline, message will be saved to offline box.
2.3, broadcast message
This will broadcast message to all users online without offline functionality.

3, whoelse
single command, server will send a list of users online. If no one, server will tell the user 'you are alone'.

4, wholast number
number must at [0,60)
Server will send a list of users who logs in within number minutes.

5, logout
User will log out on the server side, and all his information will delete. Log out message and thread information will display on both server and user side.

5,DESCRIPTION ADDITIONAL FUNCTION AND HOW THEY CAN BE TESETED
1, hard exit
You don't have to use CTRL + C to log out, just close terminal to stop the program. 

2, offline message
message or broadcast to user who's offline. When the user is online, offline message will prompt to this user first with format:
time sender type(broadcast or message) msg

3, user status and check connection status
Note that in my code, there is a field called 'idle'. Every interval of time, server will send 'idle' to the user, and calculate time that user reply with 'idle'. Because sometimes socket connection is broken which can be caused by hard exit meaning user not exit with CTRL + C, and if you don't send any thing, you won't know whether the connection is broken. Also, if connection is broken, the socket.recv() will attempt to receive message and try to insist for seconds to recover the connection and this will cause socket.recv() return ''.

The thing is, you have to reply avoid key words 'idle'. Say, if you send 'whoelse' to the server, and simultaneously time_idler send 'idle' to reply server check. At the server side, sever may receive message like 'wholast 32idle', and this will cause Server to send alert to user to use 'wholast' correctly. And you should do this very carefully. And to solve this misconfusion in message, you have to use 'idle' as spliter to do with you message, pyhonic way is message.strip('idle')

And I plan to extend this with, if server send 'idle' to the user, and user can send back with message start with 'idle' like: 'idle busy'. This means the user is busy and want to block messages for a time. Then, the status of the user will be busy and all the message he or she receives will be stored into his offline box. When the user change his status to online, the user can send 'idle online' to the server. Once the user is online again, message in his offline box will prompt to this user immediately.

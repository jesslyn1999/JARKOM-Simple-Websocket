# Base Framing Protocol: --------------------------------------------------------------------------
# From RFC 6455 -> RFC 5234:
"""
+-+-+-+-+-------+-+-------------+-------------------------------+
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
"""

# Dependencies: -----------------------------------------------------------------------------------
import sys
import struct
from base64 import b64encode
from hashlib import sha1
import logging
from socket import error as SocketError
import errno
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
# MD5 LIB:
from hashlib import md5
# -------------------------------------------------------------------------------------------------

# Global Var and Constant Declarations: -----------------------------------------------------------
VERSION_PYTHON_THREE = 3

logger = logging.getLogger(__name__)
logging.basicConfig()

FILE_PATH = 'submission.zip'

SERVER_PORT = 80
SERVER_HOST = '0.0.0.0' # FOR DEPLOYMENT ON AWS VIRTUAL MACHINE SAKE

# constants:
FIN = 0x80
OPCODE = 0x0f
MASKED = 0x80
PAYLOAD_LEN = 0x7f
PAYLOAD_LEN_EXT16 = 0x7e  # 126
PAYLOAD_LEN_EXT64 = 0x7f  # 127

# opcode types
OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE_CONN = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

allow_reuse_address = True  # TCP Server class's attribute
daemon_threads = True  # comment to keep threads alive until finished

clients = []
id_current_client = 0

# -------------------------------------------------------------------------------------------------

# Web Socket Server CLASS: ------------------------------------------------------------------------
class WebsocketServer(ThreadingMixIn, TCPServer):

    @classmethod
    def new_client(cls, client, server):
        # Called for every client connecting (after handshake)
        print("A client successfully established connection with server! Mapping ID %d to that client." % client['id'])
        # server.broadcast_to_all("Hey all, a new client has joined us")

    @classmethod
    def client_left(cls, client, server):
        # Called for every client disconnecting
        print("A client with ID %d broke off connection." % client['id'])

    def run_until_interrupted(self):
        try:
            logger.info("Listening on PORT %d..." % self.port)
            self.serve_forever()  # process one or many requests, inherits from TCPServer in BaseServer Class
        except KeyboardInterrupt:
            self.server_close()  # close the socket
            logger.info("Terminating server...")
        except Exception as e:
            logger.error(str(e), exc_info=True)
            exit(1)

    def _message_received_(self, handler, msg):  # server, client, msg
        client, server, message = self.find_client(handler), self, msg

        # Called when a client sends a message
        print("A client with ID %d sent a message!" % (client['id'])) # Don't print message payload here. May hinder performance and worsen score...
        message_parts = message.split(maxsplit=1)
        command = message_parts.pop(0)
        # FUNCTIONALITIES needed to be implemented as dictated by the assignment
        # First functionality: case sensitive echo
        if command == '!echo':
            if len(message_parts) > 0:
                server.send_message(client, message_parts.pop())
            else:
                server.send_message(client, '')

        # Second functinality: Recognize text payload and reply with archive containing source code and readme
        elif command == '!submission':
            with open(FILE_PATH, "rb") as f:
                read_bytes_from_file = f.read()
                server.send_message(client, read_bytes_from_file)

        # Third functionality: Recognizing and reading binary file and comparing checksums
        else:
            with open(FILE_PATH, "rb") as f:
                read_bytes_from_file = f.read()
                payload_text = '0'
                if md5(message).hexdigest() == md5(read_bytes_from_file).hexdigest():
                    payload_text = '1'
                server.send_message(client, payload_text)

    @classmethod
    def send_message(cls, client, msg):
        client['handler'].send_message(msg)

    def broadcast_to_all(self, msg):
        for client in self.clients:
            client['handler'].send_message(msg)

    """
    ThreadingMixIn mix-in classes can be used to support asynchronous behaviour
    """

    """
    The ThreadingMixIn class defines an attribute daemon_threads,
    which indicates whether or not the server should wait for thread termination
    """



    def __init__(self, port, host=SERVER_HOST, loglevel=logging.WARNING):
        logger.setLevel(loglevel)

        # Params: server_address, RequestHandlerClass
        # server_bind(), socket.bind() and server_activate(), socket.listen()
        TCPServer.__init__(self, (host, port), WebSocketRequestHandler)

        # socket.getsockname() return server local address
        self.port = self.socket.getsockname()[1]

    def _ping_received_(self, handler, msg):
        handler.send_pong(msg)

    def _pong_received_(self, handler, msg):
        pass # do nothing

    def _new_client_(self, handler):
        self.id_current_client += 1
        client = {
            'id': self.id_current_client,
            'handler': handler,
            'address': handler.client_address
        }
        self.clients.append(client)
        self.new_client(client, self)

    def _client_left_(self, handler):
        client = self.find_client(handler)
        self.client_left(client, self)
        if client in self.clients:
            self.clients.remove(client)

    def find_client(self, handler):
        for client in self.clients:
            if client['handler'] == handler:
                return client

# -------------------------------------------------------------------------------------------------

# WebSocket Request Handler CLASS: ----------------------------------------------------------------
class WebSocketRequestHandler(StreamRequestHandler):
    """
    implements setup, handle, finish method from BaseRequestHandler
    """

    def __init__(self, socket, addr, server):
        self.server = server
        StreamRequestHandler.__init__(self, socket, addr, server)  # Socket or request, client addr, server

    def setup(self):
        StreamRequestHandler.setup(self)
        self.keep_alive = True
        self.handshake_done = False
        self.valid_client = False

    def handle(self):
        """
        this method will process incoming requests
        """
        while self.keep_alive:
            if not self.handshake_done:
                self.handshake()
            elif self.valid_client:
                self.read_next_message()

    def convert_to_bytes(self, num):
        # python3 gives ordinal of byte directly
        bytes = self.rfile.read(num)
        if sys.version_info[0] < VERSION_PYTHON_THREE:
            return map(ord, bytes)
        else:
            return bytes

    def read_next_message(self):
        try:
            b1, b2 = self.convert_to_bytes(2)  ##
        except SocketError as e:  # to be replaced with ConnectionResetError for py3
            if e.errno == errno.ECONNRESET:
                logger.info("Client closed connection.")
                self.keep_alive = 0
                return
            b1, b2 = 0, 0
        except ValueError as e:
            b1, b2 = 0, 0

        fin = b1 & FIN
        opcode = b1 & OPCODE
        masked = b2 & MASKED
        payload_length = b2 & PAYLOAD_LEN

        # TURN OFF BECAUSE MAY WORSEN PERFORMANCE ACCORDING TO AUTOGRADER:
        # print("client: ", self.client_address)
        # print("fin : ", hex(fin))
        # print("opcode : ", hex(opcode))
        # print("masked : ", hex(masked))
        # print("payload_length : ", hex(payload_length))

        if opcode == OPCODE_CLOSE_CONN:
            logger.info("a client forced to close the connection.")
            self.keep_alive = 0
            return

        # The MASK bit simply tells whether the message is encoded.
        if not masked:
            # logger.warn("Client must always be masked.")
            self.keep_alive = 0
            return
        if opcode == OPCODE_CONTINUATION:
            # logger.warn("Continuation frames are not supported.")
            return
        elif opcode == OPCODE_BINARY or opcode == OPCODE_TEXT:
            opcode_handler = self.server._message_received_
        elif opcode == OPCODE_PING:
            opcode_handler = self.server._ping_received_
        elif opcode == OPCODE_PONG:
            opcode_handler = self.server._pong_received_
        else:
            logger.warn("Unrecognized op-code %#x." % opcode)
            self.keep_alive = 0
            return

        if payload_length == PAYLOAD_LEN_EXT16:
            payload_length = struct.unpack(">H", self.rfile.read(2))[0]
        elif payload_length == PAYLOAD_LEN_EXT64:
            payload_length = struct.unpack(">Q", self.rfile.read(8))[0]

        masks = self.convert_to_bytes(4)
        message_bytes = bytearray()
        for message_byte in self.convert_to_bytes(payload_length):
            message_byte ^= masks[len(message_bytes) % 4]
            message_bytes.append(message_byte)

        if opcode == OPCODE_TEXT:
            opcode_handler(self, message_bytes.decode('utf8'))
        else:
            opcode_handler(self, message_bytes)

    def send_message(self, message):
        self.send_binary_text(message)

    def send_pong(self, message):
        self.send_binary_text(message, OPCODE_PONG)

    def send_binary_text(self, message, opcode=OPCODE_BINARY):
        """
        Important: Fragmented(=continuation) messages are not supported since
        their usage cases are limited - when we don't know the payload length.
        """

        # Validate message
        # if isinstance(message, bytes):
        #     message = utf8_decoding(message)  # this is slower but ensures we have UTF-8
        #     if not message:
        #         logger.warning("Can\'t send message, message is not valid UTF-8")
        #         return False
        # elif sys.version_info < (3, 0) and (isinstance(message, str) or isinstance(message, unicode)):
        #     pass
        # elif isinstance(message, str):
        #     pass
        # else:
        #     logger.warning('Can\'t send message, message
        #     has to be a string or bytes. Given type is %s' % type(message))
        #     return False

        payload = message

        if isinstance(message, str):
            opcode = OPCODE_TEXT
            payload = utf8_encoding(message)

        header = bytearray()
        payload_length = len(payload)

        # Normal payload
        if payload_length <= 125:
            header.append(FIN | opcode)
            header.append(payload_length)

        # Extended payload
        elif payload_length >= PAYLOAD_LEN_EXT16 and payload_length <= 65535:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT16)
            header.extend(struct.pack(">H", payload_length))

        # Huge extended payload
        elif payload_length < 18446744073709551616:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT64)
            header.extend(struct.pack(">Q", payload_length))

        else:
            raise Exception("Message size too huge... split it first plz")
            return

        self.request.send(header + payload)

    def handshake(self):
        headers = {}
        # first line should be HTTP GET
        http_get = self.rfile.readline().decode().strip()
        assert http_get.upper().startswith('GET')
        # the rest should be headers
        while True:
            header = self.rfile.readline().decode().strip()
            if not header:
                break
            head, value = header.split(':', 1)
            headers[head.lower().strip()] = value.strip()

        try:
            assert headers['upgrade'].lower() == 'websocket'
        except AssertionError:  # handshake fails then terminate the loop in request handler
            self.keep_alive = False
            return

        try:
            key = headers['sec-websocket-key']
        except KeyError:
            logger.warning("A client tried to establish a connection but didn't have any key")
            self.keep_alive = False
            return

        response = self.make_handshake_response(key)

        # request.send() ~ socket.send()  return number of bytes sent
        self.handshake_done = self.request.send(response.encode())
        self.valid_client = True
        self.server._new_client_(self)

    @classmethod
    def make_handshake_response(cls, key):
        GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        hash = sha1(key.encode() + GUID.encode())
        response_key = b64encode(hash.digest()).strip()
        mod_response = response_key.decode('ASCII')
        return \
            'HTTP/1.1 101 Switching Protocols\r\n' \
            'Upgrade: websocket\r\n' \
            'Connection: Upgrade\r\n' \
            'Sec-WebSocket-Accept: %s\r\n' \
            '\r\n' % mod_response

    def finish(self):
        self.server._client_left_(self)


# HELPER FUNCTIONS: -------------------------------------------------------------------------------
def utf8_encoding(data):
    try:
        return data.encode('UTF-8')
    except UnicodeEncodeError as e:
        logger.error("Data cannot be encoded to UTF-8 -- %s" % e)
        return False
    except Exception as e:
        raise e
# -------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------

# MAIN FUNCTION: ----------------------------------------------------------------------------------
def main():
    server = WebsocketServer(host=SERVER_HOST, port=SERVER_PORT)
    server.run_until_interrupted()


main() # Calling main function, python-3.x style
# -------------------------------------------------------------------------------------------------
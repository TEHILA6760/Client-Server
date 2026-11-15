import socket
import selectors
import struct
from protocol import ProtocolHandler

class Server:
    DEFAULT_PORT = 1369
    CONFIG_PORT_PATH = 'port.info'
    HEADER_SIZE = 23 
    HEADER_FORMAT = '<16sBHI'

    def __init__(self, db_manager):
        self.db_manager = db_manager 
        self.port = self._extract_port() # חילוץ הפורט המבוקש
        self.server_socket = None #הגדרת סוקט השרת
        self.sel = selectors.DefaultSelector() # הגדרת סלקטור לניהול האירועים
        self.protocol_handler = ProtocolHandler(self.db_manager)

    def _extract_port(self):
        try: #נסיון לפתוח קובץ
            with open(self.CONFIG_PORT_PATH, 'r') as file: #פתיחת הקובץ 
                port = int(file.read().strip()) #מחזירים את מספר הפורט - ע"י קריאה מהקובץ,מחיקה של תויים לבנים מהסוף להתחלה והמרה לאינט
                if 1<= port <= 65535:
                    return port
                else:
                    print("Warning: Port ",port," is out of valid range (1-65535). Using default port.")
                    return self.DEFAULT_PORT
        except FileNotFoundError:#אם יש שגיאה במציאת הקובץ
            print("Warning: The file not found. Using default port.")
            return self.DEFAULT_PORT
        except ValueError:#אם יש שגיאה בהמרת מספר הפורט לאינט
            print("Warning: Invalid port format. Using default port.")
            return self.DEFAULT_PORT
        except Exception: #אם יש שגיאה אחרת בפתיחת הקובץ
            print("Warning: Failed to read file. Using default port.")
            return self.DEFAULT_PORT

    def accept_wrapper(self, sock,mask): # פונקציה חדשה שמקבלת את החיבור דרך הסלקטור
        client_socket, client_address = sock.accept()
        client_socket.setblocking(True) 
        self.sel.register(client_socket, selectors.EVENT_READ, data=(self.conn_request_client))# רושמים את הלקוח החדש לסלקטור להאזנה, ומעבירים את הפונקציה בתוך הדאטה
        print("New connection created from ",client_address)

    def _recv_all(self, sock, size):#קריאה מהסוקט בלולאה עד שמתקבלים כמות הבתים הנדרשת או עד שהחיבור נסגר על ידי הלקוח
        buffer = bytearray() #הקצאת חוצץ דינמי עבור הבתים הנקראים
        try:
            while len(buffer) < size:
               chunk = sock.recv(size - len(buffer)) # קוראים רק את יתרת הבתים שחסרים להשלמת הגודל המבוקש 
               if not chunk: # אם הלקוח סגר את החיבור באמצע השידור 
                   return None 
               buffer.extend(chunk) 
            return bytes(buffer)
        except (socket.error, ConnectionResetError):
            # תפיסה שקטה של ניתוק פתאומי מצד הלקוח 
            return None

    def conn_request_client(self, client_socket, mask):
        try:
            client_address = client_socket.getpeername()
            print("Received packet from ", client_address)
            header_data = self._recv_all(client_socket, self.HEADER_SIZE)
            
            if not header_data or len(header_data) < self.HEADER_SIZE:
                print("Client ", client_address, " disconnected or sent incomplete header.\n")
                self.sel.unregister(client_socket)
                client_socket.close()
                return

            client_id, version, code, payload_size = struct.unpack(self.HEADER_FORMAT, header_data)
            print("Received Request - Code: ", code, " Payload Size: ", payload_size, " bytes")

            payload = b''
            if payload_size > 0:
                # הגנה דפנסיבית לקבצים (קוד 828): נקרא תחילה רק את 12 הבתים הראשונים של גודל הקובץ!
                if code == 828 and payload_size >= 12:
                    size_header = self._recv_all(client_socket, 12)
                    if not size_header or len(size_header) < 12:
                        print("Error: Incomplete file size header from", client_address)
                        self.sel.unregister(client_socket)
                        client_socket.close()
                        return
                    
                    content_size, orig_file_size, _, _ = struct.unpack('<IIHH', size_header)
                    
                    # בדיקה דפנסיבית מיידית לפני שקוראים את כל הקובץ הענק לזיכרון!
                    if content_size > 20 * 1024 * 1024 or orig_file_size > 20 * 1024 * 1024:
                        print("Defensive Intercept: File size exceeds 20MB limit (", content_size, " bytes). Dropping client immediately.")
                        self.sel.unregister(client_socket)
                        client_socket.close()
                        return
                    
                    # אם הקובץ תקין, נמשיך לקרוא את שאר ה-payload ונחבר מחדש
                    remaining_payload_size = payload_size - 12
                    remaining_payload = self._recv_all(client_socket, remaining_payload_size) if remaining_payload_size > 0 else b''
                    payload = size_header + remaining_payload
                else:
                    payload = self._recv_all(client_socket, payload_size)
                    if not payload or len(payload) < payload_size:
                        print("Error: Incomplete payload received from", client_address)
                        self.sel.unregister(client_socket)
                        client_socket.close()
                        return

            response = self.protocol_handler.handle_request(code, client_id, payload)
            if response:
                client_socket.sendall(response)

        except Exception as err:
            print("Error handling client ", client_address, " : ", err)
            try: 
                self.sel.unregister(client_socket) 
                client_socket.close() 
            except Exception: 
                pass

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #  לשרת-TCP יצירת סוקט 
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # מאפשר להשתמש באותו פורט שוב אחרי שהשרת נסגר
        self.server_socket.bind(('0.0.0.0', self.port)) #הגדרה לאילו כתובות להאזין
        self.server_socket.listen()
        self.server_socket.setblocking(False) # הגדרת סוקט השרת כלא-חוסם עבור הסלקטור
        self.sel.register(self.server_socket, selectors.EVENT_READ, data=self.accept_wrapper)# רושמים את סוקט השרת בסלקטור כך שברגע שיש התחברות חדשה, תופעל הפונקציה accept_wrapper
        print("Server is successfully listening on port", self.port,"\n")
   
        try:
            while True:
                events = self.sel.select(timeout=None) # השרת נעצר כאן ומחכה לאירועים מכל הסוקטים המחוברים
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj,mask)
        except KeyboardInterrupt:
            print("\nServer shutting down safely...")
        finally:
            if self.server_socket:
                self.sel.unregister(self.server_socket) # הסרת שרת מהסלקטור
                self.server_socket.close() #סגירת סוקט השרת
            self.sel.close() # סגירת הסלקטור כולו





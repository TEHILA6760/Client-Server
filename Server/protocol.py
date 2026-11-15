import struct
import uuid
import os
import zlib 
import protocol_codes as codes

from datetime import datetime 
from cksum import memcrc
from Crypto.PublicKey import RSA  
from Crypto.Cipher import PKCS1_OAEP , AES

class ProtocolHandler:
    # נתוני שרת 
    SERVER_VERSION = 3 
    RESPONSE_HEADER_FORMAT = '<BHI' #פורמט הכותרת להמרה מבינארי למשתני פייתון
    RESPONSE_HEADER_SIZE = 7 #7 בתים
    MAX_FILE_SIZE = 20 * 1024 * 1024 # מגבלת גודל קובץ מקסימלית 
    MAX_PACKET_LIMIT = 65535 # מםגבלה לכמות פקטות מותרת לקובץ - הערך הגבוה ביותר שנית לייצג ב2 בתי
    BUFFER_TIMEOUT_SECONDS = 300 # זמן תפוגה לסשן הרכבה
    MAX_SESSION_BUFFER_SIZE = 25 * 1024 * 1024 # מגבלת זיכרון לסשן הרכבה בודד 

    def __init__(self, db_manager): 
        self.db_manager = db_manager #שמירת בסיס הנתונים באוביקט הנוכחי
        self.assembly_buffers = {}


    def create_response(self, response_code, payload=b''): #אריזת חבילת תשובה מלאה-מקבל קוד תשובה מהשרת ופיילוד
        payload_size = len(payload) 
        header = struct.pack(self.RESPONSE_HEADER_FORMAT, self.SERVER_VERSION, response_code, payload_size) 
        return header + payload # מחזירים בבינארי את צירוף תוכן התשובה לכותרת

    def handle_request(self, request_code, client_id, payload): #ניתוב לפונקציה המתאימה לפי קוד הבקשה
        try: 
            if request_code == codes.REQ_REGISTER: #קוד 825
                return self._handle_register(payload) 
            elif request_code == codes.REQ_PUBLIC_KEY:#קוד 826
                return self._handle_public_key(client_id, payload)
            elif request_code == codes.REQ_RECONNECT: #קוד 827
                return self._handle_reconnect(client_id, payload)
            elif request_code == codes.REQ_SEND_FILE:  # קוד 828
                return self._handle_file_upload(client_id, payload)
            elif request_code == codes.REQ_CRC_OK: # קוד 900 
                return self._handle_crc_ok(client_id, payload) 
            elif request_code == codes.REQ_CRC_RETRY: # קוד 901 
                return self._handle_crc_retry(client_id, payload) 
            elif request_code == codes.REQ_CRC_ABORT: # קוד 902 
                return self._handle_crc_fatal(client_id, payload)
            else: 
                print("Warning: Unknown or unimplemented request code: ", request_code) 
                return self.create_response(codes.RESP_GENERAL_ERROR)
        except ConnectionError as err:
            print("Protocol violation:", err)
            raise  # זריקת השגיאה הלאה ל-server_2.py כדי שינתק את הלקוח
        except Exception as err: 
            print("Error handling request in protocol layer:", err) 
            return self.create_response(codes.RESP_GENERAL_ERROR)

    def _handle_register(self, payload):#טיפול ברישום חדש של לקוח-קוד 825
        if len(payload) != 255:#בדיקה אם גודל הפיילוד תקין
            print("Registration error: Invalid payload size.") 
            return self.create_response(codes.RESP_GENERAL_ERROR)
        raw_name = payload[:255] #חילוץ 255 הבתים הראשונים
        client_name = self._extract_null_terminated_string(payload[:255])
        if not client_name: #אם התקבל שם ריק
            print("Registration error: Empty username received.") 
            return self.create_response(codes.RESP_REGISTER_FAILED)

        if self.db_manager.client_exists_by_name(client_name): #בדיקה אם השם כבר תפוס בבסיס הנתונים
            print("Registration failed: Username already exists - ", client_name) 
            return self.create_response(codes.RESP_REGISTER_FAILED)

        new_client_id = uuid.uuid4().bytes #יצירת מזהה ייחודי בגודל 16 בתים עבור שם המשתמש הזה
        self.db_manager.register_client(new_client_id, client_name)#שמירת הלקוח במערכת
        print("Registration successful: Registered user - ", client_name)
        return self.create_response(codes.RESP_REGISTER_SUCCESS, new_client_id) #החזרת תשובה יחד עם 16 הבתים של המזהה החדש

    def _handle_public_key(self, client_id, payload):#מקבלת מפתח ציבורי RSA - ויוצרת מפתח AES - קוד 826
        if len(payload) != 415:#בדיקה אם גודל הפיילוד תקין
            print("Public key error: Invalid payload size.") 
            return self.create_response(codes.RESP_GENERAL_ERROR)
        client_name = self._extract_null_terminated_string(payload[:255])
        if not client_name: 
            print("Public key error: Invalid username (missing null terminator).") 
            return self.create_response(codes.RESP_GENERAL_ERROR)

        public_key_bytes = payload[255:415] # חלוץ המפתח RSA
        if not self.db_manager.client_exists(client_id): #בדיקה אם הלקוח קיים במערכת
            print("Public key error: Client ID not found.") 
            return self.create_response(codes.RESP_GENERAL_ERROR)
        aes_key = os.urandom(32) #יצירת מפתח סימטרי AES-  אקראי בגודל 32 בתים
        try: 
            rsa_key = RSA.import_key(public_key_bytes)#מגדירים אוביקט מפתח RSA
            cipher_rsa = PKCS1_OAEP.new(rsa_key) #יוצרים אוביקט הצפנה
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)#מצפינים בעזרת אוביקט ההצפנה את AES
        except Exception as e: 
            print("Error encrypting AES key with RSA public key:", e) 
            return self.create_response(codes.RESP_GENERAL_ERROR)

        self.db_manager.update_client_keys(client_id, public_key_bytes, aes_key)#שמירת המפתחות במערכת
        print("Public key - AES key generated successfully for ",client_name)

        response_payload = client_id + encrypted_aes_key #החזרת התשובה: מזהה הלקוח+המפתח המוצפן
        return self.create_response(codes.RESP_PUBLIC_KEY_RECEIVED, response_payload)

    def _handle_reconnect(self, client_id, payload):
        if len(payload) != 255:
            return self.create_response(codes.RESP_GENERAL_ERROR)
        
        client_name = self._extract_null_terminated_string(payload[:255])
        if not client_name: 
            return self.create_response(codes.RESP_GENERAL_ERROR)

        # בדיקה האם הלקוח קיים לפי ID, ואם לא - ננסה לאתר לפי השם שלו במסד הנתונים
        if not self.db_manager.client_exists(client_id):
            resolved_id = self.db_manager.get_client_id_by_name(client_name)
            if resolved_id:
                client_id = resolved_id
            else:
               print("[",datetime.now().strftime('%Y-%m-%d %H:%M:%S'),"] Reconnect rejected: Client not found for ",client_name) 
               return self.create_response(codes.RESP_RECONNECT_REJECTED, client_id)

        public_key_bytes = self.db_manager.get_client_public_key(client_id)
        if not public_key_bytes:
            return self.create_response(codes.RESP_RECONNECT_REJECTED, client_id)

        aes_key = os.urandom(32)
        try: 
            rsa_key = RSA.import_key(public_key_bytes) 
            cipher_rsa = PKCS1_OAEP.new(rsa_key) 
            encrypted_aes_key = cipher_rsa.encrypt(aes_key) 
        except Exception as e: 
            print("Error encrypting AES key on reconnect:", e) 
            return self.create_response(codes.RESP_GENERAL_ERROR)

        self.db_manager.update_client_aes_key(client_id, aes_key)
        self.db_manager.update_last_seen(client_id)
        
        print("[",datetime.now().strftime('%Y-%m-%d %H:%M:%S'),"] Reconnect approved: New AES key generated for ",client_name)
        response_payload = client_id + encrypted_aes_key 
        return self.create_response(codes.RESP_RECONNECT_APPROVED, response_payload)

    def _cleanup_expired_sessions(self): #ניקוי אוגרי ההרכבה שלא הושלמו ועבר זמנם
        now = datetime.now() 
        abandoned_clients = [] 
        for c_id, files_dict in list(self.assembly_buffers.items()): 
            expired_files = [
                f_name for f_name, session in files_dict.items() 
                if (now - session['updated_at']).total_seconds() > self.BUFFER_TIMEOUT_SECONDS 
            ] 
            for f_name in expired_files: 
                print("Defensive cleanup: Abandoned upload for '",f_name,"' purged from memory.") 
                del files_dict[f_name] 
            if not files_dict: 
                abandoned_clients.append(c_id) 
        for c_id in abandoned_clients: 
            del self.assembly_buffers[c_id]

    def _handle_file_upload(self, client_id, payload):#מטפלת בקבלת קובץ מהלקוח - קוד 828
        if len(payload) < 267: #בדיקה אם גודל הפיילוד תקין
            print("Send file error: Payload too short.") 
            return self.create_response(codes.RESP_GENERAL_ERROR)

        content_size, orig_file_size, packet_num, total_packets = struct.unpack('<IIHH', payload[:12])#חילוץ הנתונים

        raw_filename = payload[12:267] #חילוץ שם הקובץ תחילה
        file_name = self._extract_null_terminated_string(raw_filename)
        if not file_name: 
            print("Send file error: Invalid file name (missing null terminator).") 
            return self.create_response(codes.RESP_GENERAL_ERROR)

        # בלימת קובץ מעל 20MB וניתוק מיידי של הלקוח כבר בפקטה הראשונה!
        if packet_num == 1 and (content_size > self.MAX_FILE_SIZE or orig_file_size > self.MAX_FILE_SIZE):
            print("Send file error: File size (", content_size ," bytes) exceeds 20MB limit. Dropping client.")
            raise ConnectionError("Malicious upload detected: File exceeds 20MB limit.")

        if total_packets <= 0 or total_packets > self.MAX_PACKET_LIMIT: #הגבלת כמות פקטות
            print("Defensive intercept: Invalid total_packets count ",total_packets) 
            return self.create_response(codes.RESP_GENERAL_ERROR)

        chunk_data = payload[267:] # תוכן הפקטה המוצפן  
        self._cleanup_expired_sessions() # ניקוי סשנים   
        if client_id not in self.assembly_buffers: #אתחול מפתח אגירה
            self.assembly_buffers[client_id] = {} 

        if file_name not in self.assembly_buffers[client_id]: 
            self.assembly_buffers[client_id][file_name] = { 
                'total': total_packets, 
                'content_size': content_size,
                'orig_size': orig_file_size, 
                'chunks': {}, 
                'updated_at': datetime.now() 
            } 
        session = self.assembly_buffers[client_id][file_name] 
        session['updated_at'] = datetime.now() 
        session['chunks'][packet_num] = chunk_data 
            
        current_session_bytes = sum(len(part) for part in session['chunks'].values()) #הגנת זיכרון לסשן יחיד
        if current_session_bytes > self.MAX_SESSION_BUFFER_SIZE: 
            print("Defensive intercept: Session memory limit exceeded for file '",file_name,"'.") 
            del self.assembly_buffers[client_id][file_name] 
            if not self.assembly_buffers[client_id]: 
                del self.assembly_buffers[client_id] 
            return self.create_response(codes.RESP_GENERAL_ERROR) 
            
        print("Received packet ",packet_num,"/",total_packets," for file '",file_name,"'") 
        
        # סנכרון רגיל: כל עוד לא סיימנו, שותקים ולא מציפים את הלקוח
        if len(session['chunks']) < session['total']: 
            return None 
            
        # כל הפקטות הגיעו! הרכבה מסודרת לפי אינדקס טורי 
        full_encrypted_content = b''.join( session['chunks'][idx] for idx in sorted(session['chunks'].keys()) ) 
        
        # ניקוי ה-Buffer מהזיכרון לאחר הרכבה מלאה 
        del self.assembly_buffers[client_id][file_name] 
        if not self.assembly_buffers[client_id]: 
            del self.assembly_buffers[client_id]
        
        aes_key = self.db_manager.get_client_aes_key(client_id) #שליפת מפתח AES
        if not aes_key: #אם לא קיים המפתח
            print("Send file error: AES key not found for client.") 
            return self.create_response(codes.RESP_GENERAL_ERROR)

        try: 
            iv = b'\x00' * 16 # וקטור של 16 0-ים  
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv) #יצירת אוביקט ההצפנה 
            decrypted_padded = cipher_aes.decrypt(full_encrypted_content) #פענוח הקובץ
            decrypted_content = decrypted_padded[:orig_file_size] # חיתוך הריפוד
        except Exception as e: 
            print("Error decrypting file ", file_name, e)
            return self.create_response(codes.RESP_GENERAL_ERROR)

        crc_value = memcrc(decrypted_content) #חישוב CRC של התוכן המפוענח
        try: #שמירת הקובץ המפוענח בדיסק
            os.makedirs("received_files", exist_ok=True) 
            file_path = os.path.join("received_files", file_name) 
            with open(file_path, "wb") as f:
                f.write(decrypted_content) 
            print("File '",file_name,"' saved successfully. Calculated CRC32: ",crc_value)
        except Exception as e: 
            print("Error saving file ",file_name," to disk: ", e)
            return self.create_response(codes.RESP_GENERAL_ERROR)

        self.db_manager.add_file_record(client_id, file_name, file_path, verified=False)
        response_payload = (
            client_id + 
            struct.pack('<I', content_size) + 
            raw_filename + 
            struct.pack('<I', crc_value)
        )
        return self.create_response(codes.RESP_FILE_RECEIVED, response_payload)

    def _handle_crc_ok(self, client_id, payload): #אישור קבלת המידע בהצלחה - קוד 900
        if len(payload) != 255: #בדיקה אם גודל הפיילוד תקין
            print("CRC OK error: Invalid payload size.") 
            return self.create_response(codes.RESP_GENERAL_ERROR)
        file_name = self._extract_null_terminated_string(payload[:255])
        if not file_name: 
            print("CRC OK error: Invalid file name (missing null terminator).") 
            return self.create_response(codes.RESP_GENERAL_ERROR)
        self.db_manager.set_file_verified(client_id, file_name) 
        print("CRC OK confirmed by client for file '", file_name, "'. Transfer complete.")
        return self.create_response(codes.RESP_CONFIRMED, client_id)

    def _handle_crc_retry(self, client_id, payload): #בדיקת ואישור -קוד 901CRC
        if len(payload) != 255: #בדיקה אם גודל הפיילוד תקין
            print("CRC Retry error: Invalid payload size.") 
            return self.create_response(codes.RESP_GENERAL_ERROR) 

        file_name = self._extract_null_terminated_string(payload[:255]) 
        if not file_name: 
            print("CRC Retry error: Invalid file name (missing null terminator).") 
            return self.create_response(codes.RESP_GENERAL_ERROR) 
        print("CRC Retry requested by client for file '", file_name, "'. Waiting for retransmission.") 
        return self.create_response(codes.RESP_CONFIRMED, client_id)
    
    def _handle_crc_fatal(self, client_id, payload): #שגיאה רביעית בזיהוי CRC - קוד 902
        if len(payload) != 255: #בדיקת תקינות גודל פיילוד
            print("CRC Fatal error: Invalid payload size.") 
            return self.create_response(codes.RESP_GENERAL_ERROR) 

        file_name = self._extract_null_terminated_string(payload[:255]) 
        if not file_name: 
            print("CRC Fatal error: Invalid file name (missing null terminator).") 
            return self.create_response(codes.RESP_GENERAL_ERROR) 
        print("CRC Fatal reported by client for file '", file_name, "'. File transfer aborted.") #הדפסת והחזרת שגיאה
        return self.create_response(codes.RESP_CONFIRMED, client_id)
    
    def _extract_null_terminated_string(self, raw_bytes):#חילוץ מחרוזת מתוך חוצץ בגודל קבוע
        if b'\x00' not in raw_bytes:
            return None  # חסר תו מסיים - חבילה פגומה!
        return raw_bytes.split(b'\x00')[0].decode('ascii', errors='ignore').strip()# חיתוך עד לתו ה-Null הראשון והמרה ל-ASCII






 









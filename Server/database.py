import os
import sqlite3
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_file='defensive.db', assets_dir='backup_files'):
        self.db_file = db_file
        self.assets_dir = assets_dir 
        self.clients_memory = {} 
        self.files_memory = {} 
        self.conn = None 
        self._init_storage() 

    def _init_storage(self):
        try: 
            os.makedirs(self.assets_dir, exist_ok=True) 
        except Exception as err: 
            print("Warning: Failed to create assets directory:", err)

        try: 
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False) 
            cursor = self.conn.cursor() 

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    ID BLOB VARCHAR(32) PRIMARY KEY,
                    Name VARCHAR(255) UNIQUE,
                    PublicKey BLOB(160),
                    LastSeen DATETIME,
                    AES BLOB(32)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    ID BLOB VARCHAR(32),
                    FileName VARCHAR(255),
                    PathName VARCHAR(255),
                    Verified BOOLEAN,
                    PRIMARY KEY (ID, FileName)
                )
            """)

            cursor.execute("SELECT ID, Name, PublicKey, AES FROM clients")
            for row in cursor.fetchall():
                client_uuid, client_name, public_key, aes_key = row 
                self.clients_memory[client_uuid] = { 
                    'Name': client_name,
                    'PublicKey': public_key,
                    'AES': aes_key
                }
            self.conn.commit()
            cursor.close() 
            print("[",datetime.now().strftime('%Y-%m-%d %H:%M:%S'),"] Database initialized successfully.")

        except Exception as err: 
            print("Database error during initialization:", err)

    def get_client_id_by_name(self, client_name):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT ID FROM clients WHERE Name = ?", [client_name])
            row = cursor.fetchone()
            cursor.close()
            if row and row[0]:
                return row[0]
            return None
        except Exception as e:
            print("Error fetching client ID by name:", e)
            return None

    def update_last_seen(self, client_id):
        try:
            cursor = self.conn.cursor()
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("UPDATE clients SET LastSeen = ? WHERE ID = ?", (now_str, client_id))
            self.conn.commit()
            cursor.close()
        except Exception as e:
            print("Error updating LastSeen:", e)

    def get_client_public_key(self, client_id): 
        try: 
            cursor = self.conn.cursor() 
            cursor.execute("SELECT PublicKey FROM clients WHERE ID = ?", [client_id]) 
            row = cursor.fetchone() 
            cursor.close() 
            if row and row[0]: 
                return row[0] 
            return None 
        except Exception as e: 
            print("Error fetching public key from DB:", e) 
            return None 
        
    def update_client_keys(self, client_id, public_key, aes_key): 
        try: 
            cursor = self.conn.cursor() 
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(""" 
                UPDATE clients 
                SET PublicKey = ?, AES = ?, LastSeen = ? 
                WHERE ID = ? """, 
                (public_key, aes_key, now_str, client_id)) 
            self.conn.commit() 
            cursor.close() 
            if client_id in self.clients_memory: 
                self.clients_memory[client_id]['PublicKey'] = public_key 
                self.clients_memory[client_id]['AES'] = aes_key 
        except Exception as e: 
            print("Error updating client keys in DB:", e)

    def client_exists_by_name(self, client_name):
        for client_info in self.clients_memory.values(): 
            if client_info.get('Name') == client_name:
                return True
        try: 
            cursor = self.conn.cursor()
            cursor.execute("SELECT 1 FROM clients WHERE Name = ?", [client_name])
            exists = cursor.fetchone() is not None
            cursor.close()
            return exists
        except Exception as e:
            return False

    def register_client(self, client_id, client_name):
        try:
            cursor = self.conn.cursor()
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO clients (ID, Name, LastSeen)
                VALUES (?, ?, ?)
            """, (client_id, client_name, now_str))
            self.conn.commit() 
            cursor.close()

            self.clients_memory[client_id] = {
                'Name': client_name,
                'PublicKey': None,
                'AES': None
            }
        except Exception as e:
            print("Error registering client in DB:", e)

    def client_exists(self, client_id):
        if client_id in self.clients_memory:
            return True
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT 1 FROM clients WHERE ID = ?", [client_id])
            exists = cursor.fetchone() is not None
            cursor.close()
            return exists
        except Exception as e:
            return False

    def update_client_aes_key(self, client_id, aes_key):
        try:
            cursor = self.conn.cursor()
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("UPDATE clients SET AES = ?, LastSeen = ? WHERE ID = ?", (aes_key, now_str, client_id))
            self.conn.commit()
            cursor.close()

            if client_id in self.clients_memory:
                self.clients_memory[client_id]['AES'] = aes_key
        except Exception as e:
            print("Error updating AES key in DB:", e)

    def get_client_aes_key(self, client_id):
        if client_id in self.clients_memory and self.clients_memory[client_id].get('AES'):
            return self.clients_memory[client_id]['AES']
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT AES FROM clients WHERE ID = ?", [client_id])
            row = cursor.fetchone()
            cursor.close()
            if row and row[0]:
                return row[0]
            return None
        except Exception as e:
            return None

    def add_file_record(self, client_id, file_name, file_path, verified=False):
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified)
                VALUES (?, ?, ?, ?)
            """, (client_id, file_name, file_path, verified))
            self.conn.commit()
            cursor.close()

            self.files_memory[(client_id, file_name)] = {
                'PathName': file_path,
                'Verified': verified
            }
        except Exception as e:
            print("Error adding file record:", e)

    def set_file_verified(self, client_id, file_name):
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE files 
                SET Verified = 1 
                WHERE ID = ? AND FileName = ?
            """, (client_id, file_name))
            self.conn.commit()
            cursor.close()

            if (client_id, file_name) in self.files_memory:
                self.files_memory[(client_id, file_name)]['Verified'] = True
        except Exception as e:
            print("Error setting file verified:", e)
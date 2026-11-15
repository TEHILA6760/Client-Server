
# קודי בקשות מלקוח (Client -> Server) 
REQ_REGISTER = 825 # בקשת רישום לקוח חדש 
REQ_PUBLIC_KEY = 826 # שליחת מפתח ציבורי RSA 
REQ_RECONNECT = 827 # בקשת התחברות חוזרת 
REQ_SEND_FILE = 828 # שליחת קובץ מוצפן 
REQ_CRC_OK = 900 # אישור שה-CRC תקין 
REQ_CRC_RETRY = 901 # הודעה על CRCבקשה לשליחה חוזרת) שגוי) 
REQ_CRC_ABORT = 902 # (כישלון אימות סופי (לאחר 4 ניסיונות

# קודי תשובות מהשרת (Server -> Client) 
RESP_REGISTER_SUCCESS = 1600 # רישום הצליח) מוחזר מזהה לקוח) 
RESP_REGISTER_FAILED = 1601 # רישום נכשל) משתמש קיים) 
RESP_PUBLIC_KEY_RECEIVED = 1602 # מפתח ציבורי התקבל) מוחזר מפתח AES מוצפן) 
RESP_FILE_RECEIVED = 1603 # קובץ התקבל) מוחזר חישוב CRC) 
RESP_CONFIRMED = 1604 # אישור סופי / הודעת תודה 
RESP_RECONNECT_APPROVED = 1605 # התחברות חוזרת אושרה) מוחזר מפתח AES מוצפן) 
RESP_RECONNECT_REJECTED = 1606 # התחברות חוזרת נדחתה) נדרש רישום) 
RESP_GENERAL_ERROR = 1607 # שגיאת שרת כללית
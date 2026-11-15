#ifndef PROTOCOL_H_ 
#define PROTOCOL_H_
#include <cstdint>

#pragma pack(push, 1)
// כותרת בקשת לקוח
struct RequestHeader {
	uint8_t version = 3; // גרסת הפרוטוקול של הלקוח 
	uint16_t code; // קוד הבקשה
	uint32_t payload_size; // גודל גוף ההודעה בבתים
};

// כותרת תשובת שרת
struct ResponseHeader {
	uint8_t version; // גרסת הפרוטוקול של השרת (1 בית) 
	uint16_t code; // קוד התגובה מהשרת (2 בתים) 
	uint32_t payload_size; // גודל גוף התשובה בבתים (4 בתים) 
};
#pragma pack(pop)

// קבועי קודי הבקשות שמועברים מהלקוח לשרת
namespace RequestCode {
	constexpr uint16_t REGISTER = 825; // בקשת רישום לקוח חדש 
	constexpr uint16_t SEND_PUBLIC_KEY = 826; // שליחת מפתח ציבורי RSA 
	constexpr uint16_t RECONNECT = 827; // בקשת התחברות חוזרת 
	constexpr uint16_t SEND_FILE = 828; // שליחת קובץ מוצפן 
	constexpr uint16_t CRC_VALID = 900; // אישור שה-CRC תקין 
	constexpr uint16_t CRC_INVALID_RETRY = 901; // CRC לא תקין - ניסיון שליחה חוזר 
	constexpr uint16_t CRC_INVALID_ABORT = 902; // CRC לא תקין בפעם ה-4 - ביטול 
}

// קבועי קודי התשובות שמתקבלים מהשרת
namespace ResponseCode {
	constexpr uint16_t REGISTER_SUCCESS = 1600; // רישום הצליח 
	constexpr uint16_t REGISTER_FAILED = 1601; // רישום נכשל 
	constexpr uint16_t PUBLIC_KEY_RECEIVED = 1602; // התקבל מפתח ציבורי ונשלח AES 
	constexpr uint16_t FILE_RECEIVED_CRC = 1603; // קובץ התקבל ונשלח CRC32 
	constexpr uint16_t CONFIRM_GENERIC = 1604; // אישור קבלת הודעה 
	constexpr uint16_t RECONNECT_APPROVED = 1605; // התחברות חוזרת אושרה ונשלח AES 
	constexpr uint16_t RECONNECT_REJECTED = 1606; // התחברות חוזרת נדחתה 
	constexpr uint16_t GENERAL_ERROR = 1607; // שגיאה כללית בשרת 
}

#endif /* PROTOCOL_H_ */
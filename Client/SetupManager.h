#ifndef SETUP_MANAGER_H 
#define SETUP_MANAGER_H

#include <string>
#include <vector>
#include <cstdint>

struct TransferInfo { 
	std::string serverIp; 
	uint16_t serverPort = 0; 
	std::string clientName; 
	std::string filePath; 
	std::vector<std::string> filePaths;
};

struct ClientInfo {
	std::string clientName; 
	uint8_t clientId[16] = {}; // 16 בתים
	std::string clientIdHex;        // 32 תווי Hex
	std::string privateKey;
	bool isRegistered = false;//סטטוס רישום
};

class SetupManager {
private: 
	TransferInfo config; 
	ClientInfo identity;
public:
	SetupManager();
	bool loadTransferInfo(const std::string& filename = "transfer.json");//קריאת הקובץ טרנפר וחילוץ הנתונים מתוכו
	static bool existsMeInfo(const std::string& filename = "me.info");//בדיקה אם me.info קיים
	bool loadMeInfo(const std::string& filename = "me.info"); //קריאת הנתונים מתוך me.info
	bool saveMeInfo(const std::string& filename = "me.info");// שמירת me.info אחרי רישום מוצלח לשרת
	static bool savePrivateKey(const std::string& filename, const std::string& privKey);//שמירת המפתח הפרטי לקובץ
	bool loadPrivateKey(const std::string& filename, std::string& privKey); //טעינת המפתח הרפטי מקובץ
	bool loadPrivateKey(const std::string& filename = "priv.key");//אם לא קיים הקובץ פרייב קי
	static std::vector<uint8_t> hexToBytes(const std::string& hex); //המרת מחרוזת בהקסדיצמלי לבתים
	static std::string bytesToHex(const std::vector<uint8_t>& bytes); // המרת מחרוזת מבתים להקסדצימלי
	static std::string trim(const std::string& str);//מחיקת תווים לבנים מסוף ותחילת מחרוזת
	const TransferInfo& getConfig() const;
	const ClientInfo& getIdentity() const;
};

#endif // SETUP_MANAGER_H

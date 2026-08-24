#pragma once

#if defined(__APPLE__) || defined(__unix__)
#define VMP_IMPORT 
#define VMP_API
#define VMP_WCHAR unsigned short
#else
#define VMP_IMPORT __declspec(dllimport)
#define VMP_API __stdcall
#define VMP_WCHAR wchar_t
#define VMP_U8(value) u8##value
#ifdef _VMP
#	define VMP_BEGIN(label)                                       VMProtectBegin(label)
#	define VMP_BEGIN_VIRTUALIZATION(label)                        VMProtectBeginVirtualization(label)
#	define VMP_BEGIN_MUTATION(label)                              VMProtectBeginMutation(label)
#	define VMP_BEGIN_ULTRA(label)                                 VMProtectBeginUltra(label)
#	define VMP_BEGIN_VIRTUALIZATION_LOCK_BY_KEY(label)            VMProtectBeginVirtualizationLockByKey(label)
#	define VMP_BEGIN_ULTRA_LOCK_BY_KEY(labe)                      VMProtectBeginUltraLockByKey(label)
#	define VMP_END()                                              VMProtectEnd()

#	define VMP_IS_PROTECTED()                                     VMProtectIsProtected()
#	define VMP_IS_DEBUGGER_PRESENT(b)                             VMProtectIsDebuggerPresent(b)
#	define VMP_IS_VIRTUAL_MACHINE_PRESENT()                       VMProtectIsVirtualMachinePresent()
#	define VMP_IS_VALID_IMAGE_CRC()                               VMProtectIsValidImageCRC()
#	define VMP_STRA(value)                                        VMProtectDecryptStringA(value)
#	define VMP_STRW(value)                                        VMProtectDecryptStringW(value)
#	define VMP_STRU8(value)										  VMProtectDecryptStringA((PCH)VMP_U8(value))
#	define VMP_FREESTR(value)                                     VMProtectFreeString(value)

#	define VMP_SET_SERIAL_NUMBER(serial)                          VMProtectSetSerialNumber(serial)
#	define VMP_GET_SERIAL_NUMBER()                                VMProtectGetSerialNumberState()
#	define VMP_GET_SERIAL_NUMBER_DATA(data, size)                 VMProtectGetSerialNumberData(data, size)
#	define VMP_GET_CURRENT_HWID(hwid, size)                       VMProtectGetCurrentHWID(hwid, size)

#	define VMP_ACTIVATE_LICENSE(code, serial, size)               VMProtectActivateLicense(code, serial, size)
#	define VMP_DEACTIVATE_LICENSE(serial)                         VMProtectDeactivateLicense(serial)
#	define VMP_GET_OFFLINE_ACTIVATION_STRING(code, buf, size)     VMProtectGetOfflineActivationString(code, buf, size)
#	define VMP_GET_OFFLINE_DEACTIVATION_STRING(serial, buf, size) VMProtectGetOfflineDeactivationString(serial, buf, size)
#else
#	define VMP_BEGIN(label)
#	define VMP_BEGIN_VIRTUALIZATION(label)
#	define VMP_BEGIN_MUTATION(label)
#	define VMP_BEGIN_ULTRA(label)
#	define VMP_BEGIN_VIRTUALIZATION_LOCK_BY_KEY(label)
#	define VMP_BEGIN_ULTRA_LOCK_BY_KEY(labe)
#	define VMP_END()

#	define VMP_IS_PROTECTED()									  true
#	define VMP_IS_DEBUGGER_PRESENT(b)							  false
#	define VMP_IS_VIRTUAL_MACHINE_PRESENT()						  false
#	define VMP_IS_VALID_IMAGE_CRC()								  true
#	define VMP_STRA(value)										  value
#	define VMP_STRW(value)										  value
#	define VMP_STRU8(value)										  value
#	define VMP_FREESTR(value)

#	define VMP_SET_SERIAL_NUMBER(serial)                          0
#	define VMP_GET_SERIAL_NUMBER()                                0
#	define VMP_GET_SERIAL_NUMBER_DATA(data, size)                 true
#	define VMP_GET_CURRENT_HWID(hwid, size)                       0

#	define VMP_ACTIVATE_LICENSE(code, serial, size)               0
#	define VMP_DEACTIVATE_LICENSE(serial)                         0
#	define VMP_GET_OFFLINE_ACTIVATION_STRING(code, buf, size)     0
#	define VMP_GET_OFFLINE_DEACTIVATION_STRING(serial, buf, size) 0

#	ifdef _UNICODE
#		define VMP_STR VMP_STRW
#	else
#		define VMP_STR VMP_STRA
#	endif
#endif
// #ifdef _WIN64
// 	#pragma comment(lib, "VMProtectSDK64.lib")
// #else
// 	#pragma comment(lib, "VMProtectSDK32.lib")
// #endif // _WIN64
#endif // __APPLE__ || __unix__

#ifdef __cplusplus
extern "C" {
#endif

// protection
VMP_IMPORT void VMP_API VMProtectBegin(const char *);
VMP_IMPORT void VMP_API VMProtectBeginVirtualization(const char *);
VMP_IMPORT void VMP_API VMProtectBeginMutation(const char *);
VMP_IMPORT void VMP_API VMProtectBeginUltra(const char *);
VMP_IMPORT void VMP_API VMProtectBeginVirtualizationLockByKey(const char *);
VMP_IMPORT void VMP_API VMProtectBeginUltraLockByKey(const char *);
VMP_IMPORT void VMP_API VMProtectEnd(void);

// utils
VMP_IMPORT bool VMP_API VMProtectIsProtected();
VMP_IMPORT bool VMP_API VMProtectIsDebuggerPresent(bool);
VMP_IMPORT bool VMP_API VMProtectIsVirtualMachinePresent(void);
VMP_IMPORT bool VMP_API VMProtectIsValidImageCRC(void);
VMP_IMPORT const char * VMP_API VMProtectDecryptStringA(const char *value);
VMP_IMPORT const VMP_WCHAR * VMP_API VMProtectDecryptStringW(const VMP_WCHAR *value);
VMP_IMPORT bool VMP_API VMProtectFreeString(const void *value);

// licensing
enum VMProtectSerialStateFlags
{
	SERIAL_STATE_SUCCESS				= 0,
	SERIAL_STATE_FLAG_CORRUPTED			= 0x00000001,
	SERIAL_STATE_FLAG_INVALID			= 0x00000002,
	SERIAL_STATE_FLAG_BLACKLISTED		= 0x00000004,
	SERIAL_STATE_FLAG_DATE_EXPIRED		= 0x00000008,
	SERIAL_STATE_FLAG_RUNNING_TIME_OVER	= 0x00000010,
	SERIAL_STATE_FLAG_BAD_HWID			= 0x00000020,
	SERIAL_STATE_FLAG_MAX_BUILD_EXPIRED	= 0x00000040,
};

#pragma pack(push, 1)
typedef struct
{
	unsigned short	wYear;
	unsigned char	bMonth;
	unsigned char	bDay;
} VMProtectDate;

typedef struct
{
	int				nState;				// VMProtectSerialStateFlags
	VMP_WCHAR		wUserName[256];		// user name
	VMP_WCHAR		wEMail[256];		// email
	VMProtectDate	dtExpire;			// date of serial number expiration
	VMProtectDate	dtMaxBuild;			// max date of build, that will accept this key
	int				bRunningTime;		// running time in minutes
	unsigned char	nUserDataLength;	// length of user data in bUserData
	unsigned char	bUserData[255];		// up to 255 bytes of user data
} VMProtectSerialNumberData;
#pragma pack(pop)

VMP_IMPORT int VMP_API VMProtectSetSerialNumber(const char *serial);
VMP_IMPORT int VMP_API VMProtectGetSerialNumberState();
VMP_IMPORT bool VMP_API VMProtectGetSerialNumberData(VMProtectSerialNumberData *data, int size);
VMP_IMPORT int VMP_API VMProtectGetCurrentHWID(char *hwid, int size);

// activation
enum VMProtectActivationFlags
{
	ACTIVATION_OK = 0,
	ACTIVATION_SMALL_BUFFER,
	ACTIVATION_NO_CONNECTION,
	ACTIVATION_BAD_REPLY,
	ACTIVATION_BANNED,
	ACTIVATION_CORRUPTED,
	ACTIVATION_BAD_CODE,
	ACTIVATION_ALREADY_USED,
	ACTIVATION_SERIAL_UNKNOWN,
	ACTIVATION_EXPIRED,
	ACTIVATION_NOT_AVAILABLE
};

VMP_IMPORT int VMP_API VMProtectActivateLicense(const char *code, char *serial, int size);
VMP_IMPORT int VMP_API VMProtectDeactivateLicense(const char *serial);
VMP_IMPORT int VMP_API VMProtectGetOfflineActivationString(const char *code, char *buf, int size);
VMP_IMPORT int VMP_API VMProtectGetOfflineDeactivationString(const char *serial, char *buf, int size);

#ifdef __cplusplus
}
#endif

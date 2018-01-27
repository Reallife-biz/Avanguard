#include "stdafx.h"
#include "HWIDsUtils.h"

#define AddHwidEntry(Hwid, Value) if ((Value)) (Hwid) += (Value)

UINT64 GetHWID() {
	std::string Hwid;

	DWORD CPUID = GetCPUID();

	FIRMWARE_INFO Firmware = { 0 };
	if (GetFirmwareInfo(&Firmware)) {
		// Baseboard:
		AddHwidEntry(Hwid, Firmware.BaseboardData.AssetTag);
		AddHwidEntry(Hwid, Firmware.BaseboardData.LocationInChassis);
		AddHwidEntry(Hwid, Firmware.BaseboardData.Manufactorer);
		AddHwidEntry(Hwid, Firmware.BaseboardData.Product);
		AddHwidEntry(Hwid, Firmware.BaseboardData.SerialNumber);
		AddHwidEntry(Hwid, Firmware.BaseboardData.Version);

		// BIOS:
		AddHwidEntry(Hwid, Firmware.BIOSData.BIOSVersion);
		AddHwidEntry(Hwid, Firmware.BIOSData.ReleaseDate);
		AddHwidEntry(Hwid, Firmware.BIOSData.Vendor);

		// SystemInfo:
		AddHwidEntry(Hwid, Firmware.SystemData.Family);
		AddHwidEntry(Hwid, Firmware.SystemData.Manufactorer);
		AddHwidEntry(Hwid, Firmware.SystemData.ProductName);
		AddHwidEntry(Hwid, Firmware.SystemData.SerialNumber);
		AddHwidEntry(Hwid, Firmware.SystemData.SKUNumber);
		AddHwidEntry(Hwid, Firmware.SystemData.Version);

		FreeFirmwareInfo(&Firmware);
	}

	return t1ha(Hwid.c_str(), Hwid.length(), CPUID);
}

#undef AddHwidEntry
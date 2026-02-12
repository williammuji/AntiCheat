#include <gtest/gtest.h>

#include "sensors/MemorySecuritySensor.h"

class MemorySecuritySensorTestAccess
{
public:
    static bool IsKnownSafeRegion(uintptr_t base, SIZE_T size)
    {
        return MemorySecuritySensor::IsKnownSafeRegion(base, size);
    }

    static bool CheckHiddenRegionHasPe(MemorySecuritySensor &sensor, PVOID base, SIZE_T size)
    {
        return sensor.CheckHiddenMemoryRegion(base, size).shouldReport;
    }
    static bool IsRwX(DWORD protect)
    {
        return MemorySecuritySensor::IsRwXProtection(protect);
    }
    static bool IsRxOnly(DWORD protect)
    {
        return MemorySecuritySensor::IsRxOnlyProtection(protect);
    }
    static bool ShouldSkipLowAddressRwx(uintptr_t base, SIZE_T size)
    {
        return MemorySecuritySensor::ShouldSkipLowAddressSmallRwx(base, size);
    }
};

TEST(SensorMemorySecurityTest, KnownSafeRegionRules)
{
    EXPECT_TRUE(MemorySecuritySensorTestAccess::IsKnownSafeRegion(0x1000, 4096));
    EXPECT_TRUE(MemorySecuritySensorTestAccess::IsKnownSafeRegion(0x7FFE1000, 4096));
    EXPECT_FALSE(MemorySecuritySensorTestAccess::IsKnownSafeRegion(0x500000, 64 * 1024));
}

TEST(SensorMemorySecurityTest, HiddenRegionPeSignatureTriggersReport)
{
    MemorySecuritySensor sensor;
    std::vector<unsigned char> fake(128 * 1024, 0);
    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(fake.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;
    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS *>(fake.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
#ifdef _WIN64
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
#else
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
#endif
    EXPECT_TRUE(MemorySecuritySensorTestAccess::CheckHiddenRegionHasPe(sensor, fake.data(), fake.size()));
}

TEST(SensorMemorySecurityTest, RwxRxClassificationHelpers)
{
    EXPECT_TRUE(MemorySecuritySensorTestAccess::IsRwX(PAGE_EXECUTE_READWRITE));
    EXPECT_TRUE(MemorySecuritySensorTestAccess::IsRwX(PAGE_EXECUTE_WRITECOPY));
    EXPECT_FALSE(MemorySecuritySensorTestAccess::IsRwX(PAGE_EXECUTE_READ));

    EXPECT_TRUE(MemorySecuritySensorTestAccess::IsRxOnly(PAGE_EXECUTE_READ));
    EXPECT_FALSE(MemorySecuritySensorTestAccess::IsRxOnly(PAGE_EXECUTE_READWRITE));
}

TEST(SensorMemorySecurityTest, LowAddressSmallRwxSkipHelper)
{
    EXPECT_TRUE(MemorySecuritySensorTestAccess::ShouldSkipLowAddressRwx(0x100000, 4096));
    EXPECT_FALSE(MemorySecuritySensorTestAccess::ShouldSkipLowAddressRwx(0x400000, 4096));
    EXPECT_FALSE(MemorySecuritySensorTestAccess::ShouldSkipLowAddressRwx(0x100000, 128 * 1024));
}

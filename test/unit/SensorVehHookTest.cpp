#include <gtest/gtest.h>

#include "sensors/VehHookSensor.h"

class VehHookSensorTestAccess
{
public:
    static VehHookSensor::VehAccessResult Access(uintptr_t base, SystemUtils::WindowsVersion version)
    {
        return VehHookSensor::AccessVehStructSafe(base, version);
    }

    static VehHookSensor::VehTraverseResult Traverse(LIST_ENTRY *head, int budgetMs)
    {
        return VehHookSensor::TraverseVehListSafe(head, budgetMs);
    }
    static bool IsExecutable(DWORD prot)
    {
        return VehHookSensor::IsExecutableProtection(prot);
    }
    static std::wstring FileNameLower(const std::wstring &path)
    {
        return VehHookSensor::ExtractLowerModuleFileName(path);
    }
};

TEST(SensorVehHookTest, AccessVehStructSafeReturnsHeadForKnownLayouts)
{
    VECTORED_HANDLER_LIST_WIN8 list = {};
    list.ExceptionList.Flink = &list.ExceptionList;
    list.ExceptionList.Blink = &list.ExceptionList;

    const auto result = VehHookSensorTestAccess::Access(
        reinterpret_cast<uintptr_t>(&list), SystemUtils::WindowsVersion::Win_10);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.pHead, &list.ExceptionList);
}

TEST(SensorVehHookTest, TraverseVehListCollectsHandlers)
{
    VECTORED_HANDLER_ENTRY entry = {};
    LIST_ENTRY head = {};

    head.Flink = &entry.List;
    head.Blink = &entry.List;
    entry.List.Flink = &head;
    entry.List.Blink = &head;
    entry.Handler = reinterpret_cast<PVOID>(0x12345678);

    const auto result = VehHookSensorTestAccess::Traverse(&head, 100);
    EXPECT_TRUE(result.success);
    ASSERT_EQ(result.handlerCount, 1);
    EXPECT_EQ(result.handlers[0], entry.Handler);
}

TEST(SensorVehHookTest, ExecutableProtectionClassification)
{
    EXPECT_TRUE(VehHookSensorTestAccess::IsExecutable(PAGE_EXECUTE_READ));
    EXPECT_TRUE(VehHookSensorTestAccess::IsExecutable(PAGE_EXECUTE_READWRITE));
    EXPECT_FALSE(VehHookSensorTestAccess::IsExecutable(PAGE_READWRITE));
}

TEST(SensorVehHookTest, ExtractLowerModuleFileName)
{
    EXPECT_EQ(VehHookSensorTestAccess::FileNameLower(L"C:\\Windows\\System32\\KERNEL32.DLL"), L"kernel32.dll");
    EXPECT_EQ(VehHookSensorTestAccess::FileNameLower(L"ntdll.dll"), L"ntdll.dll");
}

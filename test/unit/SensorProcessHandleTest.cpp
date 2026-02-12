#include <gtest/gtest.h>

#include "sensors/ProcessHandleSensor.h"

class ProcessHandleSensorTestAccess
{
public:
    using Buffer = ProcessHandleSensor::HandleBufferManager;
    static bool HasSuspiciousAccess(ULONG access)
    {
        return ProcessHandleSensor::HasSuspiciousProcessAccessMask(access);
    }
    static bool IsSevereOverflow(ULONG_PTR total, ULONG max)
    {
        return ProcessHandleSensor::IsSevereHandleOverflow(total, max);
    }
    static bool ShouldAbortByRetry(int retries)
    {
        return ProcessHandleSensor::ShouldAbortDueToRetryCount(retries);
    }
};

TEST(SensorProcessHandleTest, BufferManagerResizesAndRespectsLimits)
{
    ProcessHandleSensorTestAccess::Buffer buffer;
    ASSERT_NE(buffer.buffer, nullptr);
    ASSERT_GT(buffer.size, static_cast<size_t>(0));

    const size_t initialSize = buffer.size;
    EXPECT_TRUE(buffer.Resize(initialSize * 2));
    EXPECT_GT(buffer.size, initialSize);
}

TEST(SensorProcessHandleTest, AccessMaskClassification)
{
    EXPECT_FALSE(ProcessHandleSensorTestAccess::HasSuspiciousAccess(PROCESS_QUERY_INFORMATION));
    EXPECT_TRUE(ProcessHandleSensorTestAccess::HasSuspiciousAccess(PROCESS_VM_READ));
    EXPECT_TRUE(ProcessHandleSensorTestAccess::HasSuspiciousAccess(PROCESS_VM_WRITE));
}

TEST(SensorProcessHandleTest, OverflowAndRetryBoundaries)
{
    EXPECT_FALSE(ProcessHandleSensorTestAccess::IsSevereOverflow(140, 100));
    EXPECT_TRUE(ProcessHandleSensorTestAccess::IsSevereOverflow(150, 100));
    EXPECT_TRUE(ProcessHandleSensorTestAccess::IsSevereOverflow(1, 0));

    EXPECT_FALSE(ProcessHandleSensorTestAccess::ShouldAbortByRetry(3));
    EXPECT_TRUE(ProcessHandleSensorTestAccess::ShouldAbortByRetry(4));
}

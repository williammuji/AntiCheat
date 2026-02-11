#include "../include/ISensor.h"
#include "../include/ScanContext.h"

bool ISensor::IsOsSupported(ScanContext &context) const
{
    return context.IsCurrentOsSupported();
}

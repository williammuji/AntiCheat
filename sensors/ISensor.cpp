#include "ISensor.h"
#include "ScanContext.h"

bool ISensor::IsOsSupported(ScanContext &context) const
{
    return context.IsCurrentOsSupported();
}

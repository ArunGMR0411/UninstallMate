namespace UninstallMate.Models;

public enum OwnershipConfidence
{
    Low = 0,
    Medium = 1,
    High = 2,
    Certain = 3
}

public static class OwnershipConfidenceExtensions
{
    public static bool IsAtLeast(this OwnershipConfidence actual, OwnershipConfidence required)
        => actual >= required;

    public static OwnershipConfidence Strongest(OwnershipConfidence a, OwnershipConfidence b)
        => a >= b ? a : b;

    public static OwnershipConfidence Weakest(OwnershipConfidence a, OwnershipConfidence b)
        => a <= b ? a : b;
}

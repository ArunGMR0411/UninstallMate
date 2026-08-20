namespace UninstallMate.Models;

public sealed class ScanStatusAccumulator
{
    public ScanStatus Status { get; private set; } = ScanStatus.Complete;

    public void MarkPartial()
    {
        if (Status is ScanStatus.Complete or ScanStatus.CompleteWithWarnings)
            Status = ScanStatus.Partial;
    }

    public void MarkAccessDenied()
    {
        if (Status is not ScanStatus.Failed)
            Status = ScanStatus.AccessDenied;
    }

    public void MarkFailed()
    {
        Status = ScanStatus.Failed;
    }

    public void MarkWarning()
    {
        if (Status == ScanStatus.Complete)
            Status = ScanStatus.CompleteWithWarnings;
    }
}

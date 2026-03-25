namespace ADSelfService_API.Server;

/// <summary>
/// Lors d’un clonage, l’UI préremplit souvent l’UPN de l’utilisateur source alors que le sAMAccountName change.
/// L’UPN doit être unique dans la forêt AD ; on recalcule la partie locale si l’UPN soumis est encore celui de la source.
/// Miroir PHP : intranet_normalize_clone_user_principal_name (intranet.php, intranet_dev.php).
/// </summary>
public static class UserPrincipalNameCloneNormalization
{
    public static string NormalizeSubmittedUpnForClone(
        string submittedUpn,
        string newSamAccountName,
        string sourceSamAccountName,
        string? sourceUserPrincipalName)
    {
        submittedUpn = submittedUpn?.Trim() ?? "";
        newSamAccountName = newSamAccountName?.Trim() ?? "";
        sourceSamAccountName = sourceSamAccountName?.Trim() ?? "";
        sourceUserPrincipalName = sourceUserPrincipalName?.Trim();

        if (string.IsNullOrEmpty(submittedUpn) || string.IsNullOrEmpty(newSamAccountName))
            return submittedUpn;

        if (string.IsNullOrEmpty(sourceUserPrincipalName) || sourceUserPrincipalName.IndexOf('@') < 0)
            return submittedUpn;

        var atSrc = sourceUserPrincipalName.IndexOf('@');
        var srcSuffix = sourceUserPrincipalName[(atSrc + 1)..];

        if (string.Equals(newSamAccountName, sourceSamAccountName, StringComparison.OrdinalIgnoreCase))
            return submittedUpn;

        if (string.Equals(submittedUpn, sourceUserPrincipalName, StringComparison.OrdinalIgnoreCase))
            return $"{newSamAccountName}@{srcSuffix}";

        var atSub = submittedUpn.IndexOf('@');
        if (atSub <= 0 || atSub >= submittedUpn.Length - 1)
            return submittedUpn;

        var local = submittedUpn[..atSub];
        var subSuffix = submittedUpn[(atSub + 1)..];

        if (string.Equals(local, sourceSamAccountName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(subSuffix, srcSuffix, StringComparison.OrdinalIgnoreCase))
            return $"{newSamAccountName}@{srcSuffix}";

        return submittedUpn;
    }
}

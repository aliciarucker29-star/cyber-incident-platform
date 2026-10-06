#include "MitreMapper.h"

std::vector<MitreMapping> MitreMapper::map(
    const Incident& incident
) const
{
    std::vector<MitreMapping> mappings;

    for (const std::string& rule : incident.detectionRules)
    {
        // Repeated failed authentication attempts are
        // consistent with password guessing behavior.
        if (rule == "Repeated Failed Authentication")
        {
            MitreMapping mapping;

            mapping.techniqueId = "T1110.001";
            mapping.techniqueName = "Password Guessing";
            mapping.tactic = "Credential Access";
            mapping.confidence = "high";

            mapping.reason =
                "Repeated failed authentication attempts "
                "against the same account are consistent "
                "with password guessing behavior.";

            mappings.push_back(mapping);
        }

        // A sequence of failed logins followed by success
        // may indicate successful use of valid credentials.
        if (rule == "Failed Logins Followed by Success")
        {
            MitreMapping mapping;

            mapping.techniqueId = "T1078";
            mapping.techniqueName = "Valid Accounts";
            mapping.tactic = "Initial Access";
            mapping.confidence = "medium";

            mapping.reason =
                "Multiple failed authentication attempts "
                "followed by a successful login may indicate "
                "use of valid credentials. This mapping is "
                "possible, not proof of account compromise.";

            mappings.push_back(mapping);
        }
    }

    return mappings;
}
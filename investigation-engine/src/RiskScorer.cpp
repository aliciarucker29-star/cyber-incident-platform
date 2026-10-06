#include "RiskScorer.h"

#include <algorithm>

RiskAssessment RiskScorer::calculate(
    const Incident& incident,
    const std::vector<Indicator>& indicators
) const
{
    RiskAssessment assessment;

    assessment.score = 0;

    // --------------------------------------------------
    // 1. Base score from incident severity
    // --------------------------------------------------

    if (incident.severity == "critical")
    {
        assessment.score += 40;
        assessment.reasons.push_back(
            "Critical-severity incident: +40"
        );
    }
    else if (incident.severity == "high")
    {
        assessment.score += 30;
        assessment.reasons.push_back(
            "High-severity incident: +30"
        );
    }
    else if (incident.severity == "medium")
    {
        assessment.score += 20;
        assessment.reasons.push_back(
            "Medium-severity incident: +20"
        );
    }
    else if (incident.severity == "low")
    {
        assessment.score += 10;
        assessment.reasons.push_back(
            "Low-severity incident: +10"
        );
    }

    // --------------------------------------------------
    // 2. Multiple correlated detection rules
    // --------------------------------------------------

    if (incident.detectionRules.size() >= 2)
    {
        assessment.score += 20;

        assessment.reasons.push_back(
            "Multiple correlated detection rules: +20"
        );
    }

    // --------------------------------------------------
    // 3. Failed logins followed by successful login
    // --------------------------------------------------

    bool failedThenSuccess = false;

    for (const std::string& detection :
         incident.detectionRules)
    {
        if (detection ==
            "Failed Logins Followed by Success")
        {
            failedThenSuccess = true;
            break;
        }
    }

    if (failedThenSuccess)
    {
        assessment.score += 25;

        assessment.reasons.push_back(
            "Failed authentication followed by successful login: +25"
        );
    }

    // --------------------------------------------------
    // 4. Public/external IP observed
    // --------------------------------------------------

    bool publicIpObserved = false;

    for (const Indicator& indicator : indicators)
    {
        if (indicator.type == "ip_address" &&
            indicator.reputation != "private")
        {
            publicIpObserved = true;
            break;
        }
    }

    if (publicIpObserved)
    {
        assessment.score += 15;

        assessment.reasons.push_back(
            "Public IP address observed in incident evidence: +15"
        );
    }

    // --------------------------------------------------
    // Keep risk score between 0 and 100
    // --------------------------------------------------

    assessment.score =
        std::clamp(assessment.score, 0, 100);

    assessment.level =
        determineLevel(assessment.score);

    return assessment;
}

std::string RiskScorer::determineLevel(int score) const
{
    if (score >= 80)
    {
        return "critical";
    }

    if (score >= 60)
    {
        return "high";
    }

    if (score >= 30)
    {
        return "medium";
    }

    return "low";
}
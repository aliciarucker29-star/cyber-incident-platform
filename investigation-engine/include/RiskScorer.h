#ifndef RISK_SCORER_H
#define RISK_SCORER_H

#include "Incident.h"
#include "Indicator.h"

#include <string>
#include <vector>

struct RiskAssessment
{
int score;
std::string level;
std::vector<std::string> reasons;
};

class RiskScorer
{
public:
RiskAssessment calculate(
const Incident& incident,
const std::vector<Indicator>& indicators
) const;

private:
std::string determineLevel(int score) const;
};

#endif
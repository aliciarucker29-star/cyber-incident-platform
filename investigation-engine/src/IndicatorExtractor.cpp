#include "IndicatorExtractor.h"
#include "Indicator.h"

#include <unordered_set>

std::vector<Indicator> IndicatorExtractor::extract(
const Incident& incident,
const std::vector<Event>& events
) const
{
std::vector<Indicator> indicators;

std::unordered_set<long long> evidenceIds(
incident.evidenceEventIds.begin(),
incident.evidenceEventIds.end()
);

std::unordered_set<std::string> uniqueIps;

for (const Event& event : events)
{
if (evidenceIds.find(event.eventId) == evidenceIds.end())
{
continue;
}

if (event.sourceIp.empty())
{
continue;
}

if (uniqueIps.insert(event.sourceIp).second)
{
Indicator indicator;

indicator.type = "ip_address";
indicator.value = event.sourceIp;
indicator.source = "incident_evidence";
indicator.reputation = "unknown";
indicator.confidence = 100;
indicator.context =
"IP address observed in incident evidence";

indicators.push_back(indicator);
}
}

return indicators;
}
#include "Correlator.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>

std::vector<Incident> Correlator::correlate(
const std::vector<DetectionResult>& detections,
const std::vector<Event>& events
) const
{
std::vector<Incident> incidents;

// Group successful detections by username.
std::unordered_map<
std::string,
std::vector<const DetectionResult*>
> detectionsByUser;

for (const DetectionResult& detection : detections)
{
if (!detection.detected ||
detection.username.empty())
{
continue;
}

detectionsByUser[detection.username]
.push_back(&detection);
}

long long nextIncidentId = 1;

// Create one incident for each detected user.
for (const auto& entry : detectionsByUser)
{
const std::string& username = entry.first;
const std::vector<const DetectionResult*>& userDetections =
entry.second;

Incident incident;

incident.incidentId = nextIncidentId++;
incident.title = "Suspicious Authentication Activity";
incident.username = username;
incident.severity = "high";

std::unordered_set<long long> uniqueEvidenceIds;

// Combine this user's detections and evidence.
for (const DetectionResult* detection : userDetections)
{
incident.detectionRules.push_back(
detection->ruleName
);

for (long long eventId : detection->eventIds)
{
uniqueEvidenceIds.insert(eventId);
}
}

for (long long eventId : uniqueEvidenceIds)
{
incident.evidenceEventIds.push_back(eventId);
}

std::sort(
incident.evidenceEventIds.begin(),
incident.evidenceEventIds.end()
);

bool firstEvidenceEvent = true;
long long earliestTime = 0;
long long latestTime = 0;

// Derive incident details only from evidence events.
for (const Event& event : events)
{
if (uniqueEvidenceIds.find(event.eventId)
== uniqueEvidenceIds.end())
{
continue;
}

long long eventTime =
event.timestampToEpoch();

if (eventTime < 0)
{
continue;
}

if (incident.sourceIp.empty())
{
incident.sourceIp = event.sourceIp;
}

if (incident.hostname.empty())
{
incident.hostname = event.hostname;
}

if (firstEvidenceEvent)
{
earliestTime = eventTime;
latestTime = eventTime;

incident.startTime =
event.eventTimestamp;

incident.endTime =
event.eventTimestamp;

firstEvidenceEvent = false;
}
else
{
if (eventTime < earliestTime)
{
earliestTime = eventTime;

incident.startTime =
event.eventTimestamp;
}

if (eventTime > latestTime)
{
latestTime = eventTime;

incident.endTime =
event.eventTimestamp;
}
}
}

incidents.push_back(incident);
}

return incidents;
}
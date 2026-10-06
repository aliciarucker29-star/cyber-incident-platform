#include "Timeline.h"

#include <algorithm>
#include <iostream>
#include <unordered_set>

std::vector<TimelineEntry> Timeline::build(
const Incident& incident,
const std::vector<Event>& events
) const
{
std::vector<TimelineEntry> timeline;

std::unordered_set<long long> evidenceIds(
incident.evidenceEventIds.begin(),
incident.evidenceEventIds.end()
);

// Create structured timeline entries from evidence events.
for (const Event& event : events)
{
if (evidenceIds.find(event.eventId)
== evidenceIds.end())
{
continue;
}

TimelineEntry entry;

entry.eventId = event.eventId;
entry.timestamp = event.eventTimestamp;
entry.action = event.action;
entry.username = event.username;
entry.sourceIp = event.sourceIp;
entry.hostname = event.hostname;

// Create a simple investigator-friendly description.
if (event.action == "login_failed")
{
entry.description =
"Failed authentication attempt";
}
else if (event.action == "login_success")
{
entry.description =
"Successful authentication";
}
else
{
entry.description =
"Security event";
}

timeline.push_back(entry);
}

// Sort chronologically.
// Event ID is used as a tie-breaker when timestamps are identical.
std::sort(
timeline.begin(),
timeline.end(),
[](const TimelineEntry& a,
const TimelineEntry& b)
{
if (a.timestamp == b.timestamp)
{
return a.eventId < b.eventId;
}

return a.timestamp < b.timestamp;
}
);

return timeline;
}

void Timeline::display(
const std::vector<TimelineEntry>& timeline
) const
{
std::cout << "\n=== INCIDENT TIMELINE ===\n";

for (const TimelineEntry& entry : timeline)
{
std::cout
<< "Event " << entry.eventId
<< " | "
<< entry.timestamp
<< " | "
<< entry.action
<< " | "
<< entry.username
<< " | "
<< entry.sourceIp
<< " | "
<< entry.hostname
<< " | "
<< entry.description
<< '\n';
}
}

nlohmann::json Timeline::toJson(
const std::vector<TimelineEntry>& timeline
) const
{
   nlohmann::json jsonTimeline =
     nlohmann::json::array();

for (const TimelineEntry& entry : timeline)
{
nlohmann::json jsonEntry;

jsonEntry["event_id"] =
entry.eventId;

jsonEntry["timestamp"] =
entry.timestamp;

jsonEntry["action"] =
entry.action;

jsonEntry["username"] =
entry.username;

jsonEntry["source_ip"] =
entry.sourceIp;

jsonEntry["hostname"] =
entry.hostname;

jsonEntry["description"] =
entry.description;

jsonTimeline.push_back(jsonEntry);
}

return jsonTimeline;
}
    
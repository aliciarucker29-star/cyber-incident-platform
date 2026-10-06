#ifndef TIMELINE_H
#define TIMELINE_H

#include "Event.h"
#include "Incident.h"

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

struct TimelineEntry
{
long long eventId;
std::string timestamp;
std::string action;
std::string username;
std::string sourceIp;
std::string hostname;
std::string description;
};

class Timeline
{
public:
std::vector<TimelineEntry> build(
const Incident& incident,
const std::vector<Event>& events
) const;

void display(
const std::vector<TimelineEntry>& timeline
) const;

nlohmann::json toJson(
const std::vector<TimelineEntry>& timeline
) const;

};

#endif

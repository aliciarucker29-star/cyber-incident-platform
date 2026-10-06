#include "EventLoader.h"

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::vector<Event> EventLoader::loadFromJson(
const std::string& filename
) const
{
std::vector<Event> events;

std::ifstream file(filename);

if (!file.is_open())
{
std::cerr
<< "Error: Could not open "
<< filename
<< '\n';

return events;
}

try
{
json data;

file >> data;

if (!data.contains("events") ||
!data["events"].is_array())
{
std::cerr
<< "Error: JSON does not contain "
<< "an events array.\n";

return events;
}

for (const auto& item : data["events"])
{
Event event(
item.value("event_id", 0LL),
item.value("event_timestamp", ""),
item.value("event_type", ""),
item.value("action", ""),
item.value("username", ""),
item.value("source_ip", ""),
item.value("hostname", ""),
item.value("severity", ""),
item.value("source_system", "")
);

events.push_back(event);
}
}
catch (const json::exception& e)
{
std::cerr
<< "JSON error: "
<< e.what()
<< '\n';
}

return events;
}
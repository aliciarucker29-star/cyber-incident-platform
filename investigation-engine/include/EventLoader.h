#ifndef EVENT_LOADER_H
#define EVENT_LOADER_H

#include "Event.h"
#include <string>
#include <vector>

class EventLoader
{
public:
std::vector<Event> loadFromJson(
const std::string& filename
) const;
};

#endif
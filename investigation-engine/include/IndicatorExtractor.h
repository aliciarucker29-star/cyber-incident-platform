#pragma once

#include "Event.h"
#include "Incident.h"
#include "Indicator.h"

#include <vector>

class IndicatorExtractor
{
public:
std::vector<Indicator> extract(
const Incident& incident,
const std::vector<Event>& events
) const;
};


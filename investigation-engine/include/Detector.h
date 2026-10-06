#ifndef DETECTOR_H
#define DETECTOR_H

#include "Event.h"
#include <string>
#include <vector>

struct DetectionResult
{
    bool detected;
    std::string ruleName;
    std::string description;
    std::string severity;
    std::string username;
    std::vector<long long> eventIds;
};

class Detector
{
public:
std::vector<DetectionResult> detectFailedLogins(
   const std::vector<Event>& events
) const; 

std::vector<DetectionResult> detectFailedThenSuccess(
   const std::vector<Event>& events
) const;   
};
#endif
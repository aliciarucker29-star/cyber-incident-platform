#ifndef CORRELATOR_H
#define CORRELATOR_H

#include "Detector.h"
#include "Event.h"
#include "Incident.h"

#include <vector>

class Correlator
{
public:
std::vector<Incident> correlate(
const std::vector<DetectionResult>& detections,
const std::vector<Event>& events
) const;
};

#endif